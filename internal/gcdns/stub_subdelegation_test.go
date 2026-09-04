package gcdns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func stubReferralReply(query *dns.Msg, zone, nsHost string, glue dns.RR) *dns.Msg {
	reply := new(dns.Msg)
	reply.SetReply(query)
	reply.Ns = []dns.RR{&dns.NS{
		Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
		Ns:  dns.Fqdn(nsHost),
	}}
	if glue != nil {
		reply.Extra = []dns.RR{glue}
	}
	return reply
}

func TestDelegatingStubResolverFollowsInDomainGlueReferral(t *testing.T) {
	root := "192.0.2.20:53"
	child := "192.0.2.21:53"
	var queries []string
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		require.False(t, query.RecursionDesired)
		queries = append(queries, server+"|"+dns.Fqdn(query.Question[0].Name))
		switch server {
		case root:
			return stubReferralReply(query, "branch.corp.internal.", "ns.branch.corp.internal.", &dns.A{
				Hdr: dns.RR_Header{Name: "ns.branch.corp.internal.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   []byte{192, 0, 2, 21},
			}), nil
		case child:
			reply := new(dns.Msg)
			reply.SetReply(query)
			reply.Authoritative = true
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{10, 0, 0, 10}}}
			return reply, nil
		default:
			return nil, errors.New("unexpected stub target")
		}
	})
	resolver, err := NewDelegatingStubResolver(exchanger, "corp.internal.", []string{root}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("host.branch.corp.internal.", dns.TypeA)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, child, res.Source[len("stub:"):])
	require.Equal(t, 60*time.Second, res.CacheTTL)
	require.Equal(t, DNSSECIndeterminate, res.DNSSECStatus)
	require.Equal(t, []string{root + "|host.branch.corp.internal.", child + "|host.branch.corp.internal."}, queries)
}

func TestDelegatingStubResolverResolvesSiblingNameserverInsideStubZone(t *testing.T) {
	root := "192.0.2.20:53"
	child := "192.0.2.21:53"
	malicious := "203.0.113.66:53"
	var maliciousQueries, addressQueries int
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		q := query.Question[0]
		if server == malicious {
			maliciousQueries++
			return nil, errors.New("sibling Additional address must not be trusted")
		}
		if server == child {
			reply := new(dns.Msg)
			reply.SetReply(query)
			reply.Authoritative = true
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 45}, A: []byte{10, 0, 0, 11}}}
			return reply, nil
		}
		if server != root {
			return nil, errors.New("unexpected sibling-stub target")
		}
		if equalName(q.Name, "host.branch.corp.internal.") {
			return stubReferralReply(query, "branch.corp.internal.", "ns.corp.internal.", &dns.A{
				Hdr: dns.RR_Header{Name: "ns.corp.internal.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   []byte{203, 0, 113, 66},
			}), nil
		}
		if equalName(q.Name, "ns.corp.internal.") {
			addressQueries++
			reply := new(dns.Msg)
			reply.SetReply(query)
			reply.Authoritative = true
			if q.Qtype == dns.TypeA {
				reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 21}}}
			}
			return reply, nil
		}
		return nil, errors.New("unexpected root stub query")
	})
	resolver, err := NewDelegatingStubResolver(exchanger, "corp.internal.", []string{root}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("host.branch.corp.internal.", dns.TypeA)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 2, addressQueries)
	require.Zero(t, maliciousQueries)
	require.Equal(t, "stub:"+child, res.Source)
}

func TestDelegatingStubResolverRejectsNameserverOutsideStubZone(t *testing.T) {
	root := "192.0.2.20:53"
	malicious := "203.0.113.66:53"
	var maliciousQueries int
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		if server == malicious {
			maliciousQueries++
			return nil, errors.New("external nameserver must not be queried")
		}
		if server != root {
			return nil, errors.New("unexpected external-stub target")
		}
		return stubReferralReply(query, "branch.corp.internal.", "ns.external.test.", &dns.A{
			Hdr: dns.RR_Header{Name: "ns.external.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{203, 0, 113, 66},
		}), nil
	})
	resolver, err := NewDelegatingStubResolver(exchanger, "corp.internal.", []string{root}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("host.branch.corp.internal.", dns.TypeA)
	_, err = resolver.Resolve(context.Background(), req)
	require.ErrorContains(t, err, "no resolvable nameserver addresses")
	require.Zero(t, maliciousQueries)
}

func TestDelegatingStubResolverRejectsNonCloserReferral(t *testing.T) {
	root := "192.0.2.20:53"
	exchanger := exchangeFunc(func(_ context.Context, _ string, query *dns.Msg) (*dns.Msg, error) {
		return stubReferralReply(query, "corp.internal.", "ns.corp.internal.", &dns.A{
			Hdr: dns.RR_Header{Name: "ns.corp.internal.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{192, 0, 2, 20},
		}), nil
	})
	resolver, err := NewDelegatingStubResolver(exchanger, "corp.internal.", []string{root}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("host.branch.corp.internal.", dns.TypeA)
	_, err = resolver.Resolve(context.Background(), req)
	require.ErrorContains(t, err, "is not closer than current authority")
}

func TestDelegatingStubResolverFailsOverNonAuthoritativeTerminalResponse(t *testing.T) {
	bad := "192.0.2.20:53"
	good := "192.0.2.21:53"
	var attempts []string
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		attempts = append(attempts, server)
		reply := new(dns.Msg)
		reply.SetReply(query)
		reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: []byte{10, 0, 0, 12}}}
		if server == good {
			reply.Authoritative = true
		}
		return reply, nil
	})
	resolver, err := NewDelegatingStubResolver(exchanger, "corp.internal.", []string{bad, good}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("host.corp.internal.", dns.TypeA)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, []string{bad, good}, attempts)
	require.Equal(t, "stub:"+good, res.Source)
}

func TestDelegatingStubResolverClearsAuthenticatedData(t *testing.T) {
	root := "192.0.2.20:53"
	exchanger := exchangeFunc(func(_ context.Context, _ string, query *dns.Msg) (*dns.Msg, error) {
		reply := new(dns.Msg)
		reply.SetReply(query)
		reply.Authoritative = true
		reply.AuthenticatedData = true
		reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: []byte{10, 0, 0, 13}}}
		return reply, nil
	})
	resolver, err := NewDelegatingStubResolver(exchanger, "corp.internal.", []string{root}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("host.corp.internal.", dns.TypeA)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.False(t, res.Message.AuthenticatedData)
	require.Equal(t, DNSSECIndeterminate, res.DNSSECStatus)
}
