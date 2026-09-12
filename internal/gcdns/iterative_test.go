package gcdns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type exchangeFunc func(context.Context, string, *dns.Msg) (*dns.Msg, error)

func (f exchangeFunc) Exchange(ctx context.Context, server string, msg *dns.Msg) (*dns.Msg, error) {
	return f(ctx, server, msg)
}

func TestIterativeResolverFollowsReferral(t *testing.T) {
	root := "192.0.2.53:53"
	child := "192.0.2.80:53"
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		reply := new(dns.Msg)
		reply.SetReply(query)
		require.False(t, query.RecursionDesired)
		switch server {
		case root:
			reply.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1.example.test."}}
			reply.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 80}}}
			return reply, nil
		case child:
			reply.Authoritative = true
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: []byte{192, 0, 2, 10}}}
			return reply, nil
		default:
			return nil, errors.New("unexpected target")
		}
	})
	resolver, err := NewIterativeResolver(exchanger, IterativeResolverConfig{RootServers: []string{root}, MaxDepth: 8, AttemptTimeout: time.Second, MaxConcurrent: 2})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("www.example.test.", dns.TypeA)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, child, res.Source)
	require.Equal(t, 120*time.Second, res.CacheTTL)
	require.Len(t, res.Message.Answer, 1)
}

func TestReferralTargetsAcceptInBailiwickGlue(t *testing.T) {
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS}, Ns: "ns1.example.test."},
		&dns.NS{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS}, Ns: "ns2.example.test."},
	}
	msg.Extra = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.test.", Rrtype: dns.TypeA}, A: []byte{192, 0, 2, 1}},
		&dns.AAAA{Hdr: dns.RR_Header{Name: "ns2.example.test.", Rrtype: dns.TypeAAAA}, AAAA: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}},
	}
	zone, servers, err := referralTargets(msg, "www.example.test.")
	require.NoError(t, err)
	require.Equal(t, "example.test.", zone)
	require.ElementsMatch(t, []string{"192.0.2.1:53", "[2001:db8::2]:53"}, servers)
}

func TestReferralTargetsRejectOutOfBailiwickGlue(t *testing.T) {
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS}, Ns: "ns.external.test."}}
	msg.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns.external.test.", Rrtype: dns.TypeA}, A: []byte{192, 0, 2, 44}}}
	_, _, err := referralTargets(msg, "www.example.test.")
	require.ErrorContains(t, err, "no usable in-bailiwick glue")
}

func TestIterativeResolverDetectsDelegationLoop(t *testing.T) {
	root := "192.0.2.53:53"
	child := "192.0.2.80:53"
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		reply := new(dns.Msg)
		reply.SetReply(query)
		reply.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS}, Ns: "ns1.example.test."}}
		reply.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.test.", Rrtype: dns.TypeA}, A: []byte{192, 0, 2, 80}}}
		if server != root && server != child {
			return nil, errors.New("unexpected target")
		}
		return reply, nil
	})
	resolver, err := NewIterativeResolver(exchanger, IterativeResolverConfig{RootServers: []string{root}, MaxDepth: 8, AttemptTimeout: time.Second, MaxConcurrent: 2})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("www.example.test.", dns.TypeA)
	_, err = resolver.Resolve(context.Background(), req)
	require.ErrorContains(t, err, "delegation loop detected")
}

func TestResponseCacheTTLNegativeSOA(t *testing.T) {
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeSOA, Ttl: 600}, Minttl: 180}}
	require.Equal(t, 180*time.Second, responseCacheTTL(msg))
}

func TestDefaultRootServersContainCurrentBRoot(t *testing.T) {
	servers := DefaultRootServers()
	require.Contains(t, servers, "170.247.170.2:53")
	require.Contains(t, servers, "[2801:1b8:10::b]:53")
	require.Len(t, servers, 26)
}

func TestIterativeResolverValidation(t *testing.T) {
	ex := exchangeFunc(func(context.Context, string, *dns.Msg) (*dns.Msg, error) { return nil, nil })
	_, err := NewIterativeResolver(nil, IterativeResolverConfig{MaxDepth: 1, AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.Error(t, err)
	_, err = NewIterativeResolver(ex, IterativeResolverConfig{MaxDepth: 0, AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.Error(t, err)
	_, err = NewIterativeResolver(ex, IterativeResolverConfig{MaxDepth: 1, AttemptTimeout: 0, MaxConcurrent: 1})
	require.Error(t, err)
}
