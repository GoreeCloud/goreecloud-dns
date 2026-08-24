package gcdns

import (
	"context"
	"crypto"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func routedTrustAnchorKey(t *testing.T, zone string, flags uint16) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	privateKey, err := key.Generate(256)
	require.NoError(t, err)
	signer, ok := privateKey.(crypto.Signer)
	require.True(t, ok)
	return key, signer
}

func signRoutedTrustAnchorRRSet(t *testing.T, rrset []dns.RR, key *dns.DNSKEY, signer crypto.Signer) *dns.RRSIG {
	t.Helper()
	require.NotEmpty(t, rrset)
	sig := &dns.RRSIG{
		Algorithm:  key.Algorithm,
		Inception:  uint32(nsec3TestNow.Add(-time.Hour).Unix()),
		Expiration: uint32(nsec3TestNow.Add(time.Hour).Unix()),
		KeyTag:     key.KeyTag(),
		SignerName: key.Hdr.Name,
	}
	require.NoError(t, sig.Sign(signer, rrset))
	return sig
}

func TestPrivateTrustAnchorResolverAuthenticatesApexAndTerminalAnswer(t *testing.T) {
	zone := "corp.internal."
	qname := "host.corp.internal."
	ksk, kskSigner := routedTrustAnchorKey(t, zone, dns.ZONE|dns.SEP)
	zsk, zskSigner := routedTrustAnchorKey(t, zone, dns.ZONE)
	dnskeyRRSet := []dns.RR{ksk, zsk}
	dnskeySig := signRoutedTrustAnchorRRSet(t, dnskeyRRSet, ksk, kskSigner)
	answer := &dns.A{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{10, 0, 0, 10}}
	answerSig := signRoutedTrustAnchorRRSet(t, []dns.RR{answer}, zsk, zskSigner)
	var calls int
	upstream := routingResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
		calls++
		require.True(t, req.Message.CheckingDisabled)
		require.Equal(t, "device-a", req.ClientID)
		require.Equal(t, netip.MustParseAddr("10.20.30.40"), req.ClientIP)
		q := req.Message.Question[0]
		reply := new(dns.Msg)
		reply.SetReply(req.Message)
		reply.Authoritative = true
		reply.AuthenticatedData = true
		switch q.Qtype {
		case dns.TypeDNSKEY:
			require.True(t, equalName(q.Name, zone))
			reply.Answer = []dns.RR{ksk, zsk, dnskeySig}
		case dns.TypeA:
			require.True(t, equalName(q.Name, qname))
			reply.Answer = []dns.RR{answer, answerSig}
		default:
			return nil, errors.New("unexpected private trust-anchor query")
		}
		return &Result{Message: reply, Source: "forward:192.0.2.53:53", CacheTTL: time.Minute, DNSSECStatus: DNSSECIndeterminate}, nil
	})
	resolver, err := NewPrivateTrustAnchorResolver(upstream, PrivateDNSKEYTrustAnchor{Zone: zone, Keys: []*dns.DNSKEY{ksk}}, NewDNSSECValidator(func() time.Time { return nsec3TestNow }))
	require.NoError(t, err)
	req := testRequest()
	req.ClientID = "device-a"
	req.ClientIP = netip.MustParseAddr("10.20.30.40")
	req.Message.SetQuestion(qname, dns.TypeA)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 2, calls)
	require.Equal(t, DNSSECSecure, res.DNSSECStatus)
	require.False(t, res.Message.AuthenticatedData)
	require.Equal(t, time.Minute, res.CacheTTL)
}

func TestPrivateTrustAnchorResolverIgnoresUpstreamADOnUnsignedAnswer(t *testing.T) {
	zone := "corp.internal."
	ksk, kskSigner := routedTrustAnchorKey(t, zone, dns.ZONE|dns.SEP)
	dnskeySig := signRoutedTrustAnchorRRSet(t, []dns.RR{ksk}, ksk, kskSigner)
	upstream := routingResolverFunc(func(_ context.Context, req *Request) (*Result, error) {
		q := req.Message.Question[0]
		reply := new(dns.Msg)
		reply.SetReply(req.Message)
		reply.Authoritative = true
		reply.AuthenticatedData = true
		if q.Qtype == dns.TypeDNSKEY {
			reply.Answer = []dns.RR{ksk, dnskeySig}
		} else {
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{10, 0, 0, 11}}}
		}
		return &Result{Message: reply, DNSSECStatus: DNSSECSecure}, nil
	})
	resolver, err := NewPrivateTrustAnchorResolver(upstream, PrivateDNSKEYTrustAnchor{Zone: zone, Keys: []*dns.DNSKEY{ksk}}, NewDNSSECValidator(func() time.Time { return nsec3TestNow }))
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("unsigned.corp.internal.", dns.TypeA)
	_, err = resolver.Resolve(context.Background(), req)
	require.ErrorContains(t, err, "private trust-anchor terminal validation failed")
}

func TestAuthenticateDNSKEYTrustAnchorRequiresAnchorInApexRRSet(t *testing.T) {
	zone := "corp.internal."
	anchor, _ := routedTrustAnchorKey(t, zone, dns.ZONE|dns.SEP)
	other, otherSigner := routedTrustAnchorKey(t, zone, dns.ZONE|dns.SEP)
	sig := signRoutedTrustAnchorRRSet(t, []dns.RR{other}, other, otherSigner)
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{other, sig}
	keys, status, err := NewDNSSECValidator(func() time.Time { return nsec3TestNow }).AuthenticateDNSKEYTrustAnchor(zone, msg, []*dns.DNSKEY{anchor})
	require.ErrorContains(t, err, "is not present in the apex DNSKEY RRset")
	require.Equal(t, DNSSECBogus, status)
	require.Empty(t, keys)
}

func TestAuthenticateDNSKEYTrustAnchorRequiresAnchorToSignApexRRSet(t *testing.T) {
	zone := "corp.internal."
	anchor, _ := routedTrustAnchorKey(t, zone, dns.ZONE|dns.SEP)
	zsk, zskSigner := routedTrustAnchorKey(t, zone, dns.ZONE)
	rrset := []dns.RR{anchor, zsk}
	sig := signRoutedTrustAnchorRRSet(t, rrset, zsk, zskSigner)
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{anchor, zsk, sig}
	keys, status, err := NewDNSSECValidator(func() time.Time { return nsec3TestNow }).AuthenticateDNSKEYTrustAnchor(zone, msg, []*dns.DNSKEY{anchor})
	require.Error(t, err)
	require.Equal(t, DNSSECBogus, status)
	require.Empty(t, keys)
}

func TestPrivateTrustAnchorResolverRejectsQuestionOutsideZone(t *testing.T) {
	zone := "corp.internal."
	anchor, _ := routedTrustAnchorKey(t, zone, dns.ZONE|dns.SEP)
	calls := 0
	upstream := routingResolverFunc(func(context.Context, *Request) (*Result, error) {
		calls++
		return nil, errors.New("must not query upstream")
	})
	resolver, err := NewPrivateTrustAnchorResolver(upstream, PrivateDNSKEYTrustAnchor{Zone: zone, Keys: []*dns.DNSKEY{anchor}}, NewDNSSECValidator(nil))
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("www.example.test.", dns.TypeA)
	_, err = resolver.Resolve(context.Background(), req)
	require.ErrorContains(t, err, "does not contain question")
	require.Zero(t, calls)
}

func TestPrivateTrustAnchorResolverRejectsInvalidAnchor(t *testing.T) {
	zone := "corp.internal."
	bad, _ := routedTrustAnchorKey(t, zone, dns.SEP)
	_, err := NewPrivateTrustAnchorResolver(runtimeValidationDefaultResolver(), PrivateDNSKEYTrustAnchor{Zone: zone, Keys: []*dns.DNSKEY{bad}}, NewDNSSECValidator(nil))
	require.ErrorContains(t, err, "invalid DNSKEY")
	_, err = NewPrivateTrustAnchorResolver(runtimeValidationDefaultResolver(), PrivateDNSKEYTrustAnchor{Zone: zone}, NewDNSSECValidator(nil))
	require.ErrorContains(t, err, "requires at least one DNSKEY")
	_, err = NewPrivateTrustAnchorResolver(nil, PrivateDNSKEYTrustAnchor{Zone: zone, Keys: []*dns.DNSKEY{bad}}, NewDNSSECValidator(nil))
	require.ErrorContains(t, err, "requires an upstream resolver")
}
