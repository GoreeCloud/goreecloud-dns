package gcdns

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type routingResolverFunc func(context.Context, *Request) (*Result, error)

func (f routingResolverFunc) Resolve(ctx context.Context, req *Request) (*Result, error) {
	return f(ctx, req)
}

func routingAnswer(req *Request, source string, octet byte) *Result {
	msg := new(dns.Msg)
	msg.SetReply(req.Message)
	q := req.Message.Question[0]
	msg.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{192, 0, 2, octet}}}
	return &Result{Message: msg, Source: source, CacheTTL: time.Minute, DNSSECStatus: DNSSECIndeterminate}
}

func TestRoutingResolverUsesLongestNamespaceSuffix(t *testing.T) {
	defaultCalls := 0
	defaultResolver := routingResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
		defaultCalls++
		return routingAnswer(req, "default", 1), nil
	})
	internal := routingResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
		return routingAnswer(req, "internal", 2), nil
	})
	private := routingResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
		return routingAnswer(req, "private", 3), nil
	})
	router, err := NewRoutingResolver(defaultResolver, []ResolverRoute{
		{Name: "internal", Suffix: "internal.", Mode: RouteForward, Resolver: internal},
		{Name: "private", Suffix: "private.internal.", Mode: RouteForward, Resolver: private},
	})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("host.private.internal.", dns.TypeA)
	res, err := router.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "private", res.Source)
	require.Zero(t, defaultCalls)
}

func TestRoutingResolverFallsBackToRecursiveDefault(t *testing.T) {
	defaultResolver := routingResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
		return routingAnswer(req, "recursive", 1), nil
	})
	router, err := NewRoutingResolver(defaultResolver, nil)
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("www.example.test.", dns.TypeA)
	res, err := router.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "recursive", res.Source)
}

func TestRoutingResolverRecursiveRouteOverridesBroadForward(t *testing.T) {
	defaultResolver := routingResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
		return routingAnswer(req, "recursive", 1), nil
	})
	forward := routingResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
		return routingAnswer(req, "forward", 2), nil
	})
	router, err := NewRoutingResolver(defaultResolver, []ResolverRoute{
		{Name: "forward-all", Suffix: ".", Mode: RouteForward, Resolver: forward},
		{Name: "direct-example", Suffix: "example.test.", Mode: RouteRecursive},
	})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("www.example.test.", dns.TypeA)
	res, err := router.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "recursive", res.Source)
}

func TestRoutingResolverSplitHorizonClientIDOutranksPrefix(t *testing.T) {
	defaultResolver := routingResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
		return routingAnswer(req, "default", 1), nil
	})
	global := routingResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
		return routingAnswer(req, "global", 2), nil
	})
	subnet := routingResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
		return routingAnswer(req, "subnet", 3), nil
	})
	client := routingResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
		return routingAnswer(req, "client", 4), nil
	})
	router, err := NewRoutingResolver(defaultResolver, []ResolverRoute{
		{Name: "global", Suffix: "corp.internal.", Mode: RouteForward, Resolver: global},
		{Name: "subnet", Suffix: "corp.internal.", Mode: RouteForward, Resolver: subnet, ClientPrefixes: []netip.Prefix{netip.MustParsePrefix("10.10.0.0/16")}},
		{Name: "client", Suffix: "corp.internal.", Mode: RouteForward, Resolver: client, ClientIDs: []string{"device-a"}},
	})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("service.corp.internal.", dns.TypeA)
	req.ClientID = "device-a"
	req.ClientIP = netip.MustParseAddr("10.10.20.30")
	res, err := router.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "client", res.Source)
}

func TestRoutingResolverSplitHorizonUsesLongestClientPrefix(t *testing.T) {
	defaultResolver := routingResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
		return routingAnswer(req, "default", 1), nil
	})
	wide := routingResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
		return routingAnswer(req, "wide", 2), nil
	})
	narrow := routingResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
		return routingAnswer(req, "narrow", 3), nil
	})
	router, err := NewRoutingResolver(defaultResolver, []ResolverRoute{
		{Name: "wide", Suffix: "corp.internal.", Mode: RouteForward, Resolver: wide, ClientPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
		{Name: "narrow", Suffix: "corp.internal.", Mode: RouteForward, Resolver: narrow, ClientPrefixes: []netip.Prefix{netip.MustParsePrefix("10.10.0.0/16")}},
	})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("service.corp.internal.", dns.TypeA)
	req.ClientIP = netip.MustParseAddr("10.10.20.30")
	res, err := router.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "narrow", res.Source)
}

func TestForwardingResolverSetsRDAndFailsOver(t *testing.T) {
	servers := []string{"192.0.2.10:53", "192.0.2.11:53"}
	var attempts []string
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		attempts = append(attempts, server)
		require.True(t, query.RecursionDesired)
		require.NotNil(t, query.IsEdns0())
		require.True(t, query.IsEdns0().Do())
		reply := new(dns.Msg)
		reply.SetReply(query)
		if server == servers[0] {
			reply.Rcode = dns.RcodeServerFailure
			return reply, nil
		}
		reply.AuthenticatedData = true
		reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 45}, A: []byte{192, 0, 2, 99}}}
		return reply, nil
	})
	forwarder, err := NewForwardingResolver(exchanger, servers, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	res, err := forwarder.Resolve(context.Background(), testRequest())
	require.NoError(t, err)
	require.Equal(t, servers, attempts)
	require.False(t, res.Message.AuthenticatedData)
	require.Equal(t, DNSSECIndeterminate, res.DNSSECStatus)
	require.Equal(t, 45*time.Second, res.CacheTTL)
	require.Equal(t, "forward:"+servers[1], res.Source)
}

func TestStubResolverClearsRDAndRequiresAuthoritativeTerminalResponse(t *testing.T) {
	servers := []string{"192.0.2.20:53", "192.0.2.21:53"}
	var attempts []string
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		attempts = append(attempts, server)
		require.False(t, query.RecursionDesired)
		reply := new(dns.Msg)
		reply.SetReply(query)
		if server == servers[0] {
			return reply, nil
		}
		reply.Authoritative = true
		reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: []byte{10, 0, 0, 10}}}
		return reply, nil
	})
	stub, err := NewStubResolver(exchanger, "corp.internal.", servers, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("host.corp.internal.", dns.TypeA)
	res, err := stub.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, servers, attempts)
	require.Equal(t, "stub:"+servers[1], res.Source)
	require.Equal(t, DNSSECIndeterminate, res.DNSSECStatus)
}

func TestRoutingResolverChasesAliasAcrossRoutes(t *testing.T) {
	defaultResolver := routingResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
		return routingAnswer(req, "recursive", 9), nil
	})
	stub := routingResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
		msg := new(dns.Msg)
		msg.SetReply(req.Message)
		msg.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: req.Message.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30}, Target: "public.example.test."}}
		return &Result{Message: msg, Source: "stub", CacheTTL: 30 * time.Second, DNSSECStatus: DNSSECIndeterminate}, nil
	})
	router, err := NewRoutingResolver(defaultResolver, []ResolverRoute{{Name: "internal-stub", Suffix: "corp.internal.", Mode: RouteStub, Resolver: stub}})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("alias.corp.internal.", dns.TypeA)
	res, err := router.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, res.Message.Answer, 2)
	require.Equal(t, "alias.corp.internal.", dns.Fqdn(res.Message.Question[0].Name))
	require.Equal(t, 30*time.Second, res.CacheTTL)
	// Stub data was indeterminate, so the merged chain cannot be promoted by
	// the recursive target's status.
	require.Equal(t, DNSSECIndeterminate, res.DNSSECStatus)
}

type routingDelegate struct {
	target Resolver
}

func (d *routingDelegate) Resolve(ctx context.Context, req *Request) (*Result, error) {
	if d.target == nil {
		return nil, errors.New("delegate target is nil")
	}
	return d.target.Resolve(ctx, req)
}

func TestRoutingResolverDetectsRouteLoop(t *testing.T) {
	defaultResolver := routingResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
		return routingAnswer(req, "default", 1), nil
	})
	delegate := &routingDelegate{}
	router, err := NewRoutingResolver(defaultResolver, []ResolverRoute{{Name: "loop", Suffix: "loop.internal.", Mode: RouteForward, Resolver: delegate}})
	require.NoError(t, err)
	delegate.target = router
	req := testRequest()
	req.Message.SetQuestion("host.loop.internal.", dns.TypeA)
	_, err = router.Resolve(context.Background(), req)
	require.ErrorContains(t, err, "resolver route loop detected")
}

func TestRoutingResolverRejectsAmbiguousAndInvalidConfiguration(t *testing.T) {
	defaultResolver := routingResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
		return routingAnswer(req, "default", 1), nil
	})
	target := routingResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
		return routingAnswer(req, "target", 2), nil
	})
	_, err := NewRoutingResolver(defaultResolver, []ResolverRoute{
		{Name: "one", Suffix: "internal.", Mode: RouteForward, Resolver: target},
		{Name: "two", Suffix: "internal.", Mode: RouteStub, Resolver: target},
	})
	require.ErrorContains(t, err, "ambiguous resolver routes")

	_, err = NewForwardingResolver(exchangeFunc(func(context.Context, string, *dns.Msg) (*dns.Msg, error) { return nil, nil }), []string{"not-an-endpoint"}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.ErrorContains(t, err, "invalid resolver target")
}
