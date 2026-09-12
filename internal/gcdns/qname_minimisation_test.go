package gcdns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestNextMinimisedQNAME(t *testing.T) {
	qname := "www.example.test."
	child, more, err := nextMinimisedQNAME(qname, ".")
	require.NoError(t, err)
	require.True(t, more)
	require.Equal(t, "test.", child)

	child, more, err = nextMinimisedQNAME(qname, child)
	require.NoError(t, err)
	require.True(t, more)
	require.Equal(t, "example.test.", child)

	child, more, err = nextMinimisedQNAME(qname, child)
	require.NoError(t, err)
	require.True(t, more)
	require.Equal(t, qname, child)

	_, more, err = nextMinimisedQNAME(qname, qname)
	require.NoError(t, err)
	require.False(t, more)
}

func TestNextMinimisedQNAMERejectsNonAncestorCursor(t *testing.T) {
	_, _, err := nextMinimisedQNAME("www.example.test.", "other.test.")
	require.ErrorContains(t, err, "is not an ancestor")
}

func TestQNAMEMinimisationBudgetIsBounded(t *testing.T) {
	state := newResolutionState()
	for i := 0; i < maxQNAMEMinimisationQueries; i++ {
		require.True(t, consumeQNAMEMinimisationBudget(state))
	}
	require.False(t, consumeQNAMEMinimisationBudget(state))
	require.Equal(t, maxQNAMEMinimisationQueries, state.qnameMinimisationQueries)
}

func TestQNAMEMinimisationExcludesParentSideDS(t *testing.T) {
	req := testRequest()
	req.Message.SetQuestion("example.test.", dns.TypeDS)
	require.False(t, qnameMinimisationEligible(req))
}

func TestIterativeResolverMinimisesColdReferralWalk(t *testing.T) {
	root := "192.0.2.53:53"
	tld := "192.0.2.54:53"
	auth := "192.0.2.55:53"
	var queries []dns.Question

	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		queries = append(queries, query.Question[0])
		reply := new(dns.Msg)
		reply.SetReply(query)
		q := query.Question[0]
		switch server {
		case root:
			require.Equal(t, "test.", dns.Fqdn(q.Name))
			require.Equal(t, uint16(dns.TypeA), q.Qtype)
			reply.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns.test."}}
			reply.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 54}}}
			return reply, nil
		case tld:
			require.Equal(t, "example.test.", dns.Fqdn(q.Name))
			require.Equal(t, uint16(dns.TypeA), q.Qtype)
			reply.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns.example.test."}}
			reply.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 55}}}
			return reply, nil
		case auth:
			reply.Authoritative = true
			if q.Qtype == dns.TypeA {
				require.Equal(t, "www.example.test.", dns.Fqdn(q.Name))
				return reply, nil
			}
			require.Equal(t, "www.example.test.", dns.Fqdn(q.Name))
			require.Equal(t, uint16(dns.TypeMX), q.Qtype)
			reply.Answer = []dns.RR{&dns.MX{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 90}, Preference: 10, Mx: "mail.example.test."}}
			return reply, nil
		default:
			return nil, errors.New("unexpected QNAME minimisation target")
		}
	})

	resolver, err := NewIterativeResolver(exchanger, IterativeResolverConfig{RootServers: []string{root}, MaxDepth: 8, AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("www.example.test.", dns.TypeMX)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, auth, res.Source)
	require.Equal(t, 90*time.Second, res.CacheTTL)
	require.Len(t, res.Message.Answer, 1)
	require.Len(t, queries, 4)
	require.Equal(t, "test.", dns.Fqdn(queries[0].Name))
	require.Equal(t, "example.test.", dns.Fqdn(queries[1].Name))
	require.Equal(t, "www.example.test.", dns.Fqdn(queries[2].Name))
	require.Equal(t, uint16(dns.TypeA), queries[2].Qtype)
	require.Equal(t, uint16(dns.TypeMX), queries[3].Qtype)
}

func TestIterativeResolverFallsBackAfterMinimisationBudget(t *testing.T) {
	root := "192.0.2.53:53"
	qname := "a.b.c.d.e.f.g.h.i.j.k.test."
	var queries []dns.Question
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		if server != root {
			return nil, errors.New("unexpected minimisation-budget target")
		}
		queries = append(queries, query.Question[0])
		reply := new(dns.Msg)
		reply.SetReply(query)
		reply.Authoritative = true
		q := query.Question[0]
		if q.Qtype == dns.TypeTXT {
			require.Equal(t, qname, dns.Fqdn(q.Name))
			reply.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"done"}}}
		}
		return reply, nil
	})

	resolver, err := NewIterativeResolver(exchanger, IterativeResolverConfig{RootServers: []string{root}, MaxDepth: 4, AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion(qname, dns.TypeTXT)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, res.Message.Answer, 1)
	require.Len(t, queries, maxQNAMEMinimisationQueries+1)
	for _, q := range queries[:maxQNAMEMinimisationQueries] {
		require.Equal(t, uint16(dns.TypeA), q.Qtype)
	}
	require.Equal(t, uint16(dns.TypeTXT), queries[len(queries)-1].Qtype)
	require.Equal(t, qname, dns.Fqdn(queries[len(queries)-1].Name))
}

type qnameMinimisationChain struct {
	key           *dns.DNSKEY
	terminal      func(*dns.Msg) DNSSECStatus
	dnskeyCalls   int
	terminalCalls int
}

func (c *qnameMinimisationChain) AuthenticateDNSKEYResponse(string, *dns.Msg, []*dns.DS) ([]*dns.DNSKEY, DNSSECStatus, error) {
	c.dnskeyCalls++
	return []*dns.DNSKEY{c.key}, DNSSECSecure, nil
}

func (c *qnameMinimisationChain) AuthenticateDelegationDS(string, *dns.Msg, []*dns.DNSKEY) ([]*dns.DS, DNSSECStatus, error) {
	return nil, DNSSECBogus, errors.New("unexpected delegation in QNAME minimisation validator test")
}

func (c *qnameMinimisationChain) AuthenticateTerminalAnswer(msg *dns.Msg, _ []*dns.DNSKEY) (DNSSECStatus, error) {
	c.terminalCalls++
	if c.terminal != nil {
		return c.terminal(msg), nil
	}
	return DNSSECSecure, nil
}

func TestValidatingIterativeResolverMinimisesSecureResponses(t *testing.T) {
	root := "192.0.2.53:53"
	rootKey := testDNSKEY(".", 1)
	var queries []dns.Question
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		if server != root {
			return nil, errors.New("unexpected validating minimisation target")
		}
		q := query.Question[0]
		queries = append(queries, q)
		reply := new(dns.Msg)
		reply.SetReply(query)
		reply.Authoritative = true
		if q.Qtype == dns.TypeDNSKEY && equalName(q.Name, ".") {
			reply.Answer = []dns.RR{rootKey}
			return reply, nil
		}
		if q.Qtype == dns.TypeMX {
			reply.Answer = []dns.RR{&dns.MX{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60}, Preference: 10, Mx: "mail.example.test."}}
		}
		return reply, nil
	})
	chain := &qnameMinimisationChain{key: rootKey}
	resolver, err := NewValidatingIterativeResolver(exchanger, IterativeResolverConfig{RootServers: []string{root}, MaxDepth: 4, AttemptTimeout: time.Second, MaxConcurrent: 1}, chain)
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("www.example.test.", dns.TypeMX)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, res.DNSSECStatus)
	require.Len(t, queries, 5)
	require.Equal(t, uint16(dns.TypeDNSKEY), queries[0].Qtype)
	require.Equal(t, "test.", dns.Fqdn(queries[1].Name))
	require.Equal(t, "example.test.", dns.Fqdn(queries[2].Name))
	require.Equal(t, "www.example.test.", dns.Fqdn(queries[3].Name))
	require.Equal(t, uint16(dns.TypeMX), queries[4].Qtype)
	require.Equal(t, 1, chain.dnskeyCalls)
	require.Equal(t, 4, chain.terminalCalls)
}

func TestValidatingIterativeResolverFallsBackOnIndeterminateProbe(t *testing.T) {
	root := "192.0.2.53:53"
	rootKey := testDNSKEY(".", 1)
	var queries []dns.Question
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		if server != root {
			return nil, errors.New("unexpected validating fallback target")
		}
		q := query.Question[0]
		queries = append(queries, q)
		reply := new(dns.Msg)
		reply.SetReply(query)
		reply.Authoritative = true
		if q.Qtype == dns.TypeDNSKEY {
			reply.Answer = []dns.RR{rootKey}
			return reply, nil
		}
		if q.Qtype == dns.TypeMX {
			reply.Answer = []dns.RR{&dns.MX{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60}, Preference: 10, Mx: "mail.example.test."}}
		}
		return reply, nil
	})
	chain := &qnameMinimisationChain{
		key: rootKey,
		terminal: func(msg *dns.Msg) DNSSECStatus {
			if len(msg.Question) == 1 && msg.Question[0].Qtype == dns.TypeA {
				return DNSSECIndeterminate
			}
			return DNSSECSecure
		},
	}
	resolver, err := NewValidatingIterativeResolver(exchanger, IterativeResolverConfig{RootServers: []string{root}, MaxDepth: 4, AttemptTimeout: time.Second, MaxConcurrent: 1}, chain)
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("www.example.test.", dns.TypeMX)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, res.DNSSECStatus)
	require.Len(t, queries, 3)
	require.Equal(t, uint16(dns.TypeDNSKEY), queries[0].Qtype)
	require.Equal(t, "test.", dns.Fqdn(queries[1].Name))
	require.Equal(t, uint16(dns.TypeA), queries[1].Qtype)
	require.Equal(t, "www.example.test.", dns.Fqdn(queries[2].Name))
	require.Equal(t, uint16(dns.TypeMX), queries[2].Qtype)
}
