package gcdns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestIterativeResolverReusesFinalAMinimisationProbe(t *testing.T) {
	root := "192.0.2.53:53"
	var queries []dns.Question
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		if server != root {
			return nil, errors.New("unexpected final-A reuse target")
		}
		q := query.Question[0]
		queries = append(queries, q)
		reply := new(dns.Msg)
		reply.SetReply(query)
		reply.Authoritative = true
		if equalName(q.Name, "www.example.test.") {
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{192, 0, 2, 10}}}
		}
		return reply, nil
	})

	resolver, err := NewIterativeResolver(exchanger, IterativeResolverConfig{RootServers: []string{root}, MaxDepth: 4, AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("www.example.test.", dns.TypeA)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, res.Message.Answer, 1)
	require.Equal(t, 60*time.Second, res.CacheTTL)
	require.Len(t, queries, 3)
	for _, q := range queries {
		require.Equal(t, uint16(dns.TypeA), q.Qtype)
	}
	require.Equal(t, "test.", dns.Fqdn(queries[0].Name))
	require.Equal(t, "example.test.", dns.Fqdn(queries[1].Name))
	require.Equal(t, "www.example.test.", dns.Fqdn(queries[2].Name))
}

func TestValidatingIterativeResolverReusesSecureFinalAMinimisationProbe(t *testing.T) {
	root := "192.0.2.53:53"
	rootKey := testDNSKEY(".", 1)
	var queries []dns.Question
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		if server != root {
			return nil, errors.New("unexpected secure final-A reuse target")
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
		if equalName(q.Name, "www.example.test.") {
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{192, 0, 2, 10}}}
		}
		return reply, nil
	})

	chain := &qnameMinimisationChain{key: rootKey}
	resolver, err := NewValidatingIterativeResolver(exchanger, IterativeResolverConfig{RootServers: []string{root}, MaxDepth: 4, AttemptTimeout: time.Second, MaxConcurrent: 1}, chain)
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("www.example.test.", dns.TypeA)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, res.DNSSECStatus)
	require.Len(t, res.Message.Answer, 1)
	require.Len(t, queries, 4)
	require.Equal(t, uint16(dns.TypeDNSKEY), queries[0].Qtype)
	for _, q := range queries[1:] {
		require.Equal(t, uint16(dns.TypeA), q.Qtype)
	}
	require.Equal(t, 3, chain.terminalCalls)
}
