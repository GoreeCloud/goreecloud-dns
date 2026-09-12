package gcdns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func outOfBailiwickReferral(q *dns.Msg) *dns.Msg {
	reply := new(dns.Msg)
	reply.SetReply(q)
	reply.Ns = []dns.RR{&dns.NS{
		Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
		Ns:  "ns.external.test.",
	}}
	// This address is deliberately untrusted for the example.test referral and
	// must not be used merely because it appears in Additional.
	reply.Extra = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "ns.external.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{203, 0, 113, 66},
	}}
	return reply
}

func TestBuildReferralPlanTracksOutOfBailiwickNameserver(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("www.example.test.", dns.TypeA)
	plan, err := buildReferralPlan(outOfBailiwickReferral(q), "www.example.test.")
	require.NoError(t, err)
	require.Equal(t, "example.test.", plan.zone)
	require.Empty(t, plan.servers)
	require.Equal(t, []string{"ns.external.test."}, plan.outOfBailiwickNS)
	require.Empty(t, plan.missingInDomainNS)
}

func TestBuildReferralPlanRequiresInDomainGlue(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("www.example.test.", dns.TypeA)
	reply := new(dns.Msg)
	reply.SetReply(q)
	reply.Ns = []dns.RR{&dns.NS{
		Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
		Ns:  "ns1.example.test.",
	}}
	plan, err := buildReferralPlan(reply, "www.example.test.")
	require.NoError(t, err)
	require.Empty(t, plan.servers)
	require.Empty(t, plan.outOfBailiwickNS)
	require.Equal(t, []string{"ns1.example.test."}, plan.missingInDomainNS)

	_, err = completeReferralServers(context.Background(), testRequest(), plan, newResolutionState(), func(context.Context, *Request, *resolutionState) (*Result, error) {
		t.Fatal("missing in-domain glue must not trigger circular address discovery")
		return nil, nil
	})
	require.ErrorContains(t, err, "missing mandatory in-domain glue")
}

func TestDiscoverNameServerAddressesCachesWithinResolution(t *testing.T) {
	state := newResolutionState()
	calls := 0
	resolve := func(_ context.Context, req *Request, _ *resolutionState) (*Result, error) {
		calls++
		q := req.Message.Question[0]
		msg := new(dns.Msg)
		msg.SetReply(req.Message)
		msg.Authoritative = true
		if q.Qtype == dns.TypeA {
			msg.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 80}}}
		}
		return &Result{Message: msg}, nil
	}
	first, err := discoverNameServerAddresses(context.Background(), testRequest(), "ns.external.test.", state, resolve)
	require.NoError(t, err)
	require.Equal(t, []string{"192.0.2.80:53"}, first)
	second, err := discoverNameServerAddresses(context.Background(), testRequest(), "ns.external.test.", state, resolve)
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Equal(t, 2, calls) // A and AAAA only on the first discovery.
}

func TestDiscoverNameServerAddressesRejectsActiveCycle(t *testing.T) {
	state := newResolutionState()
	state.nsActive["ns.external.test."] = struct{}{}
	_, err := discoverNameServerAddresses(context.Background(), testRequest(), "ns.external.test.", state, func(context.Context, *Request, *resolutionState) (*Result, error) {
		t.Fatal("active discovery cycle must fail before another lookup")
		return nil, nil
	})
	require.ErrorContains(t, err, "nameserver address discovery cycle")
}

func TestDiscoverNameServerAddressesEnforcesWorkLimit(t *testing.T) {
	state := newResolutionState()
	state.nsLookups = maxNameServerAddressLookups
	_, err := discoverNameServerAddresses(context.Background(), testRequest(), "ns.external.test.", state, func(context.Context, *Request, *resolutionState) (*Result, error) {
		t.Fatal("work limit must fail before another lookup")
		return nil, nil
	})
	require.ErrorContains(t, err, "work limit exceeded")
}

func TestResolvedAddressEndpointsFollowsAlias(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "ns.external.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "host.provider.test."},
		&dns.A{Hdr: dns.RR_Header{Name: "host.provider.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 80}},
	}
	require.Equal(t, []string{"192.0.2.80:53"}, resolvedAddressEndpoints(msg, "ns.external.test.", dns.TypeA))
}

func TestIterativeResolverDiscoversOutOfBailiwickNameserver(t *testing.T) {
	root := "192.0.2.53:53"
	child := "192.0.2.80:53"
	malicious := "203.0.113.66:53"
	var maliciousQueries, nsAddressQueries, childQueries int

	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		q := query.Question[0]
		if server == malicious {
			maliciousQueries++
			return nil, errors.New("untrusted Additional address must not be used")
		}
		if server == child {
			childQueries++
			reply := new(dns.Msg)
			reply.SetReply(query)
			reply.Authoritative = true
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{192, 0, 2, 10}}}
			return reply, nil
		}
		if server != root {
			return nil, errors.New("unexpected resolver target")
		}
		if dns.CanonicalName(q.Name) == "www.example.test." && q.Qtype == dns.TypeA {
			return outOfBailiwickReferral(query), nil
		}
		if dns.CanonicalName(q.Name) == "ns.external.test." {
			nsAddressQueries++
			reply := new(dns.Msg)
			reply.SetReply(query)
			reply.Authoritative = true
			if q.Qtype == dns.TypeA {
				reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 80}}}
			}
			return reply, nil
		}
		return nil, errors.New("unexpected root query")
	})

	resolver, err := NewIterativeResolver(exchanger, IterativeResolverConfig{RootServers: []string{root}, MaxDepth: 8, AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("www.example.test.", dns.TypeA)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 2, nsAddressQueries)
	require.Equal(t, 1, childQueries)
	require.Zero(t, maliciousQueries)
	require.Equal(t, child, res.Source)
	require.Len(t, res.Message.Answer, 1)
}

type discoveryChain struct {
	key *dns.DNSKEY
}

func (d *discoveryChain) AuthenticateDNSKEYResponse(string, *dns.Msg, []*dns.DS) ([]*dns.DNSKEY, DNSSECStatus, error) {
	return []*dns.DNSKEY{d.key}, DNSSECSecure, nil
}

func (d *discoveryChain) AuthenticateDelegationDS(zone string, _ *dns.Msg, _ []*dns.DNSKEY) ([]*dns.DS, DNSSECStatus, error) {
	if equalName(zone, "example.test.") {
		return nil, DNSSECInsecure, nil
	}
	return nil, DNSSECBogus, errors.New("unexpected delegation in discovery test")
}

func (d *discoveryChain) AuthenticateTerminalAnswer(*dns.Msg, []*dns.DNSKEY) (DNSSECStatus, error) {
	return DNSSECSecure, nil
}

func TestValidatingIterativeResolverDiscoversOutOfBailiwickNameserver(t *testing.T) {
	root := "192.0.2.53:53"
	child := "192.0.2.80:53"
	rootKey := testDNSKEY(".", 1)
	var childQueries int

	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		q := query.Question[0]
		if server == child {
			childQueries++
			reply := new(dns.Msg)
			reply.SetReply(query)
			reply.Authoritative = true
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{192, 0, 2, 10}}}
			return reply, nil
		}
		if server != root {
			return nil, errors.New("unexpected validating discovery target")
		}
		reply := new(dns.Msg)
		reply.SetReply(query)
		reply.Authoritative = true
		if q.Qtype == dns.TypeDNSKEY && equalName(q.Name, ".") {
			reply.Answer = []dns.RR{rootKey}
			return reply, nil
		}
		if dns.CanonicalName(q.Name) == "www.example.test." && q.Qtype == dns.TypeA {
			return outOfBailiwickReferral(query), nil
		}
		if dns.CanonicalName(q.Name) == "ns.external.test." {
			if q.Qtype == dns.TypeA {
				reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 80}}}
			}
			return reply, nil
		}
		return nil, errors.New("unexpected validating root query")
	})

	resolver, err := NewValidatingIterativeResolver(exchanger, IterativeResolverConfig{RootServers: []string{root}, MaxDepth: 8, AttemptTimeout: time.Second, MaxConcurrent: 1}, &discoveryChain{key: rootKey})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("www.example.test.", dns.TypeA)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 1, childQueries)
	require.Equal(t, DNSSECInsecure, res.DNSSECStatus)
	require.Len(t, res.Message.Answer, 1)
}
