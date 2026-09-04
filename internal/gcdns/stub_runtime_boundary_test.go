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

func TestRuntimeValidatedRouterRejectsDiscoveredStubSelfTarget(t *testing.T) {
	root := "198.51.100.20:53"
	localChild := "192.0.2.10:53"
	var localChildQueries int
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		switch server {
		case root:
			return stubReferralReply(query, "branch.corp.internal.", "ns.branch.corp.internal.", &dns.A{
				Hdr: dns.RR_Header{Name: "ns.branch.corp.internal.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   []byte{192, 0, 2, 10},
			}), nil
		case localChild:
			localChildQueries++
			return nil, errors.New("local child listener must not be queried")
		default:
			return nil, errors.New("unexpected dynamic-stub target")
		}
	})
	stub, err := NewDelegatingStubResolver(exchanger, "corp.internal.", []string{root}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	routes := []ResolverRoute{{Name: "delegating-stub", Suffix: "corp.internal.", Mode: RouteStub, Resolver: stub}}
	router, err := NewRuntimeValidatedRoutingResolver(runtimeValidationDefaultResolver(), routes, []string{"0.0.0.0:53"}, []netip.Addr{netip.MustParseAddr("192.0.2.10")})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("host.branch.corp.internal.", dns.TypeA)
	_, err = router.Resolve(context.Background(), req)
	require.ErrorContains(t, err, "points back to an active GoreeCloud DNS listener")
	require.Zero(t, localChildQueries)
}

func TestRuntimeValidatedRouterAllowsDiscoveredExternalStubTarget(t *testing.T) {
	root := "198.51.100.20:53"
	child := "198.51.100.21:53"
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		switch server {
		case root:
			return stubReferralReply(query, "branch.corp.internal.", "ns.branch.corp.internal.", &dns.A{
				Hdr: dns.RR_Header{Name: "ns.branch.corp.internal.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   []byte{198, 51, 100, 21},
			}), nil
		case child:
			reply := new(dns.Msg)
			reply.SetReply(query)
			reply.Authoritative = true
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{10, 0, 0, 20}}}
			return reply, nil
		default:
			return nil, errors.New("unexpected external dynamic-stub target")
		}
	})
	stub, err := NewDelegatingStubResolver(exchanger, "corp.internal.", []string{root}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	routes := []ResolverRoute{{Name: "delegating-stub", Suffix: "corp.internal.", Mode: RouteStub, Resolver: stub}}
	router, err := NewRuntimeValidatedRoutingResolver(runtimeValidationDefaultResolver(), routes, []string{"0.0.0.0:53"}, []netip.Addr{netip.MustParseAddr("192.0.2.10")})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("host.branch.corp.internal.", dns.TypeA)
	res, err := router.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "stub:"+child, res.Source)
}
