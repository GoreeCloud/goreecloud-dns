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

func TestPrivateTrustAnchorResolverRestoresDownstreamCD(t *testing.T) {
	zone := "corp.internal."
	qname := "host.corp.internal."
	ksk, kskSigner := routedTrustAnchorKey(t, zone, dns.ZONE|dns.SEP)
	dnskeySig := signRoutedTrustAnchorRRSet(t, []dns.RR{ksk}, ksk, kskSigner)
	answer := &dns.A{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{10, 0, 0, 40}}
	answerSig := signRoutedTrustAnchorRRSet(t, []dns.RR{answer}, ksk, kskSigner)
	upstream := routingResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
		require.True(t, req.Message.CheckingDisabled)
		reply := new(dns.Msg)
		reply.SetReply(req.Message)
		reply.Authoritative = true
		if req.Message.Question[0].Qtype == dns.TypeDNSKEY {
			reply.Answer = []dns.RR{ksk, dnskeySig}
		} else {
			reply.Answer = []dns.RR{answer, answerSig}
		}
		return &Result{Message: reply, DNSSECStatus: DNSSECIndeterminate}, nil
	})
	resolver, err := NewPrivateTrustAnchorResolver(upstream, PrivateDNSKEYTrustAnchor{Zone: zone, Keys: []*dns.DNSKEY{ksk}}, NewDNSSECValidator(func() time.Time { return nsec3TestNow }))
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion(qname, dns.TypeA)
	req.Message.CheckingDisabled = false
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.False(t, res.Message.CheckingDisabled)
}

func TestRuntimeValidationSeesThroughPrivateTrustAnchorForwarder(t *testing.T) {
	zone := "corp.internal."
	anchor, _ := routedTrustAnchorKey(t, zone, dns.ZONE|dns.SEP)
	forwarder, err := NewForwardingResolver(exchangeFunc(func(context.Context, string, *dns.Msg) (*dns.Msg, error) {
		t.Fatal("self-target validation must fail before DNS exchange")
		return nil, nil
	}), []string{"127.0.0.1:53"}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	validated, err := NewPrivateTrustAnchorResolver(forwarder, PrivateDNSKEYTrustAnchor{Zone: zone, Keys: []*dns.DNSKEY{anchor}}, NewDNSSECValidator(nil))
	require.NoError(t, err)
	routes := []ResolverRoute{{Name: "signed-private-forward", Suffix: zone, Mode: RouteForward, Resolver: validated}}
	_, err = NewRuntimeValidatedRoutingResolver(runtimeValidationDefaultResolver(), routes, []string{"127.0.0.1:53"}, nil)
	require.ErrorContains(t, err, "points back to an active GoreeCloud DNS listener")
}

func TestRuntimeValidationAttachesBoundaryThroughPrivateTrustAnchorStub(t *testing.T) {
	zone := "corp.internal."
	anchor, _ := routedTrustAnchorKey(t, zone, dns.ZONE|dns.SEP)
	stub, err := NewDelegatingStubResolver(exchangeFunc(func(context.Context, string, *dns.Msg) (*dns.Msg, error) {
		return nil, errors.New("not used")
	}), zone, []string{"198.51.100.20:53"}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	validated, err := NewPrivateTrustAnchorResolver(stub, PrivateDNSKEYTrustAnchor{Zone: zone, Keys: []*dns.DNSKEY{anchor}}, NewDNSSECValidator(nil))
	require.NoError(t, err)
	routes := []ResolverRoute{{Name: "signed-private-stub", Suffix: zone, Mode: RouteStub, Resolver: validated}}
	router, err := NewRuntimeValidatedRoutingResolver(runtimeValidationDefaultResolver(), routes, []string{"0.0.0.0:53"}, []netip.Addr{netip.MustParseAddr("192.0.2.10")})
	require.NoError(t, err)
	wrapped, ok := router.routes[0].Resolver.(*PrivateTrustAnchorResolver)
	require.True(t, ok)
	inner, ok := wrapped.resolver.(*DelegatingStubResolver)
	require.True(t, ok)
	require.NotNil(t, inner.runtimeBoundary)
}

func TestAuthenticateDNSKEYTrustAnchorRejectsNonZoneKeyAnchor(t *testing.T) {
	zone := "corp.internal."
	anchor, signer := routedTrustAnchorKey(t, zone, dns.SEP)
	sig := signRoutedTrustAnchorRRSet(t, []dns.RR{anchor}, anchor, signer)
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{anchor, sig}
	keys, status, err := NewDNSSECValidator(func() time.Time { return nsec3TestNow }).AuthenticateDNSKEYTrustAnchor(zone, msg, []*dns.DNSKEY{anchor})
	require.ErrorContains(t, err, "is not present in the apex DNSKEY RRset")
	require.Equal(t, DNSSECBogus, status)
	require.Empty(t, keys)
}

func TestPrivateTrustAnchorResolverRejectsBlankZone(t *testing.T) {
	anchor := rootKSK2017()
	_, err := NewPrivateTrustAnchorResolver(runtimeValidationDefaultResolver(), PrivateDNSKEYTrustAnchor{Zone: "   ", Keys: []*dns.DNSKEY{anchor}}, NewDNSSECValidator(nil))
	require.ErrorContains(t, err, "zone must not be blank")
}
