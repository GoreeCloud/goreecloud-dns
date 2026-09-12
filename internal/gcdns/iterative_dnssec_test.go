package gcdns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type chainAuthenticatorFunc struct {
	dnskey   func(string, *dns.Msg, []*dns.DS) ([]*dns.DNSKEY, DNSSECStatus, error)
	ds       func(string, *dns.Msg, []*dns.DNSKEY) ([]*dns.DS, DNSSECStatus, error)
	terminal func(*dns.Msg, []*dns.DNSKEY) (DNSSECStatus, error)
}

func (f chainAuthenticatorFunc) AuthenticateDNSKEYResponse(zone string, msg *dns.Msg, parentDS []*dns.DS) ([]*dns.DNSKEY, DNSSECStatus, error) {
	return f.dnskey(zone, msg, parentDS)
}

func (f chainAuthenticatorFunc) AuthenticateDelegationDS(zone string, msg *dns.Msg, parentKeys []*dns.DNSKEY) ([]*dns.DS, DNSSECStatus, error) {
	return f.ds(zone, msg, parentKeys)
}

func (f chainAuthenticatorFunc) AuthenticateTerminalAnswer(msg *dns.Msg, keys []*dns.DNSKEY) (DNSSECStatus, error) {
	if f.terminal == nil {
		return DNSSECIndeterminate, nil
	}
	return f.terminal(msg, keys)
}

func testDNSKEY(zone string, tagSeed uint16) *dns.DNSKEY {
	return &dns.DNSKEY{Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300}, Flags: 257 + tagSeed%2, Protocol: 3, Algorithm: dns.RSASHA256, PublicKey: "AQAB"}
}

func TestValidatingIterativeResolverCarriesSecureDelegationTrust(t *testing.T) {
	root := "192.0.2.53:53"
	child := "192.0.2.80:53"
	rootKey := testDNSKEY(".", 1)
	childKey := testDNSKEY("example.test.", 2)
	childDS := &dns.DS{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeDS, Class: dns.ClassINET}, KeyTag: 1234, Algorithm: dns.RSASHA256, DigestType: dns.SHA256, Digest: "00"}

	var rootDNSKEYQueries, childDNSKEYQueries int
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		reply := new(dns.Msg)
		reply.SetReply(query)
		require.False(t, query.RecursionDesired)
		require.NotNil(t, query.IsEdns0())
		require.True(t, query.IsEdns0().Do())
		q := query.Question[0]
		switch {
		case server == root && q.Qtype == dns.TypeDNSKEY && equalName(q.Name, "."):
			rootDNSKEYQueries++
			reply.Authoritative = true
			reply.Answer = []dns.RR{rootKey}
			return reply, nil
		case server == root && q.Qtype == dns.TypeA:
			reply.Ns = []dns.RR{
				&dns.NS{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1.example.test."},
				childDS,
			}
			reply.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 80}}}
			return reply, nil
		case server == child && q.Qtype == dns.TypeDNSKEY && equalName(q.Name, "example.test."):
			childDNSKEYQueries++
			reply.Authoritative = true
			reply.Answer = []dns.RR{childKey}
			return reply, nil
		case server == child && q.Qtype == dns.TypeA:
			reply.Authoritative = true
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 90}, A: []byte{192, 0, 2, 10}}}
			return reply, nil
		default:
			return nil, errors.New("unexpected DNSSEC iterative query")
		}
	})

	var dnskeyAuthCalls, dsAuthCalls, terminalAuthCalls int
	chain := chainAuthenticatorFunc{
		dnskey: func(zone string, _ *dns.Msg, parentDS []*dns.DS) ([]*dns.DNSKEY, DNSSECStatus, error) {
			dnskeyAuthCalls++
			if equalName(zone, ".") {
				require.NotEmpty(t, parentDS)
				return []*dns.DNSKEY{rootKey}, DNSSECSecure, nil
			}
			require.Equal(t, "example.test.", dns.Fqdn(zone))
			require.Equal(t, []*dns.DS{childDS}, parentDS)
			return []*dns.DNSKEY{childKey}, DNSSECSecure, nil
		},
		ds: func(zone string, _ *dns.Msg, parentKeys []*dns.DNSKEY) ([]*dns.DS, DNSSECStatus, error) {
			dsAuthCalls++
			require.Equal(t, "example.test.", dns.Fqdn(zone))
			require.Equal(t, []*dns.DNSKEY{rootKey}, parentKeys)
			return []*dns.DS{childDS}, DNSSECSecure, nil
		},
		terminal: func(_ *dns.Msg, keys []*dns.DNSKEY) (DNSSECStatus, error) {
			terminalAuthCalls++
			require.Equal(t, []*dns.DNSKEY{childKey}, keys)
			return DNSSECSecure, nil
		},
	}

	resolver, err := NewValidatingIterativeResolver(exchanger, IterativeResolverConfig{RootServers: []string{root}, MaxDepth: 8, AttemptTimeout: time.Second, MaxConcurrent: 2}, chain)
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("www.example.test.", dns.TypeA)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, child, res.Source)
	require.Equal(t, 90*time.Second, res.CacheTTL)
	require.Equal(t, DNSSECSecure, res.DNSSECStatus)
	require.Equal(t, 1, rootDNSKEYQueries)
	require.Equal(t, 1, childDNSKEYQueries)
	require.Equal(t, 2, dnskeyAuthCalls)
	require.Equal(t, 1, dsAuthCalls)
	require.Equal(t, 1, terminalAuthCalls)
}

func TestValidatingIterativeResolverCarriesProvenInsecureDelegation(t *testing.T) {
	root := "192.0.2.53:53"
	child := "192.0.2.80:53"
	rootKey := testDNSKEY(".", 1)
	var childDNSKEYQueries int
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		reply := new(dns.Msg)
		reply.SetReply(query)
		q := query.Question[0]
		switch {
		case server == root && q.Qtype == dns.TypeDNSKEY:
			reply.Authoritative = true
			reply.Answer = []dns.RR{rootKey}
			return reply, nil
		case server == root && q.Qtype == dns.TypeA:
			reply.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns1.example.test."}}
			reply.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: []byte{192, 0, 2, 80}}}
			return reply, nil
		case server == child && q.Qtype == dns.TypeDNSKEY:
			childDNSKEYQueries++
			return nil, errors.New("insecure child DNSKEY must not be fetched")
		case server == child && q.Qtype == dns.TypeA:
			reply.Authoritative = true
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{192, 0, 2, 10}}}
			return reply, nil
		default:
			return nil, errors.New("unexpected insecure-delegation query")
		}
	})
	chain := chainAuthenticatorFunc{
		dnskey: func(string, *dns.Msg, []*dns.DS) ([]*dns.DNSKEY, DNSSECStatus, error) {
			return []*dns.DNSKEY{rootKey}, DNSSECSecure, nil
		},
		ds: func(string, *dns.Msg, []*dns.DNSKEY) ([]*dns.DS, DNSSECStatus, error) {
			return nil, DNSSECInsecure, nil
		},
	}
	resolver, err := NewValidatingIterativeResolver(exchanger, IterativeResolverConfig{RootServers: []string{root}, MaxDepth: 8, AttemptTimeout: time.Second, MaxConcurrent: 1}, chain)
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("www.example.test.", dns.TypeA)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, DNSSECInsecure, res.DNSSECStatus)
	require.Equal(t, 0, childDNSKEYQueries)
}

func TestValidatingIterativeResolverFailsClosedOnUnprovenDelegation(t *testing.T) {
	root := "192.0.2.53:53"
	child := "192.0.2.80:53"
	rootKey := testDNSKEY(".", 1)
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		reply := new(dns.Msg)
		reply.SetReply(query)
		q := query.Question[0]
		if server == root && q.Qtype == dns.TypeDNSKEY {
			reply.Authoritative = true
			reply.Answer = []dns.RR{rootKey}
			return reply, nil
		}
		if server == root && q.Qtype == dns.TypeA {
			reply.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns1.example.test."}}
			reply.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: []byte{192, 0, 2, 80}}}
			return reply, nil
		}
		if server == child {
			t.Fatal("child server must not be queried after an unproven delegation")
		}
		return nil, errors.New("unexpected query")
	})
	chain := chainAuthenticatorFunc{
		dnskey: func(string, *dns.Msg, []*dns.DS) ([]*dns.DNSKEY, DNSSECStatus, error) {
			return []*dns.DNSKEY{rootKey}, DNSSECSecure, nil
		},
		ds: func(string, *dns.Msg, []*dns.DNSKEY) ([]*dns.DS, DNSSECStatus, error) {
			return nil, DNSSECIndeterminate, nil
		},
	}
	resolver, err := NewValidatingIterativeResolver(exchanger, IterativeResolverConfig{RootServers: []string{root}, MaxDepth: 8, AttemptTimeout: time.Second, MaxConcurrent: 1}, chain)
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("www.example.test.", dns.TypeA)
	_, err = resolver.Resolve(context.Background(), req)
	require.ErrorContains(t, err, "lacks authenticated DS or denial proof")
}

func TestValidatingIterativeResolverRequiresAuthenticator(t *testing.T) {
	ex := exchangeFunc(func(context.Context, string, *dns.Msg) (*dns.Msg, error) { return nil, nil })
	_, err := NewValidatingIterativeResolver(ex, IterativeResolverConfig{RootServers: []string{"192.0.2.53:53"}, MaxDepth: 1, AttemptTimeout: time.Second, MaxConcurrent: 1}, nil)
	require.ErrorContains(t, err, "requires a DNSSEC chain authenticator")
}
