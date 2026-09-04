package gcdns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestValidatingDelegatingStubResolverCarriesSecureChildTrust(t *testing.T) {
	zone := "corp.internal."
	childZone := "branch.corp.internal."
	qname := "host.branch.corp.internal."
	rootServer := "192.0.2.20:53"
	childServer := "192.0.2.21:53"

	parentKSK, parentKSKSigner := routedTrustAnchorKey(t, zone, dns.ZONE|dns.SEP)
	parentZSK, parentZSKSigner := routedTrustAnchorKey(t, zone, dns.ZONE)
	parentDNSKEYs := []dns.RR{parentKSK, parentZSK}
	parentDNSKEYSig := signRoutedTrustAnchorRRSet(t, parentDNSKEYs, parentKSK, parentKSKSigner)

	childKSK, childKSKSigner := routedTrustAnchorKey(t, childZone, dns.ZONE|dns.SEP)
	childZSK, childZSKSigner := routedTrustAnchorKey(t, childZone, dns.ZONE)
	childDS := childKSK.ToDS(dns.SHA256)
	require.NotNil(t, childDS)
	childDSSig := signRoutedTrustAnchorRRSet(t, []dns.RR{childDS}, parentZSK, parentZSKSigner)
	childDNSKEYs := []dns.RR{childKSK, childZSK}
	childDNSKEYSig := signRoutedTrustAnchorRRSet(t, childDNSKEYs, childKSK, childKSKSigner)
	answer := &dns.A{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{10, 0, 0, 50}}
	answerSig := signRoutedTrustAnchorRRSet(t, []dns.RR{answer}, childZSK, childZSKSigner)

	var childDNSKEYQueries int
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		require.False(t, query.RecursionDesired)
		require.True(t, query.CheckingDisabled)
		q := query.Question[0]
		reply := new(dns.Msg)
		reply.SetReply(query)
		reply.AuthenticatedData = true
		switch {
		case server == rootServer && q.Qtype == dns.TypeDNSKEY && equalName(q.Name, zone):
			reply.Authoritative = true
			reply.Answer = []dns.RR{parentKSK, parentZSK, parentDNSKEYSig}
			return reply, nil
		case server == rootServer && q.Qtype == dns.TypeA && equalName(q.Name, qname):
			reply.Ns = []dns.RR{
				&dns.NS{Hdr: dns.RR_Header{Name: childZone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns." + childZone},
				childDS,
				childDSSig,
			}
			reply.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns." + childZone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 21}}}
			return reply, nil
		case server == childServer && q.Qtype == dns.TypeDNSKEY && equalName(q.Name, childZone):
			childDNSKEYQueries++
			reply.Authoritative = true
			reply.Answer = []dns.RR{childKSK, childZSK, childDNSKEYSig}
			return reply, nil
		case server == childServer && q.Qtype == dns.TypeA && equalName(q.Name, qname):
			reply.Authoritative = true
			reply.Answer = []dns.RR{answer, answerSig}
			return reply, nil
		default:
			return nil, errors.New("unexpected validating stub query")
		}
	})

	resolver, err := NewValidatingDelegatingStubResolver(exchanger, zone, []string{rootServer}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1}, PrivateDNSKEYTrustAnchor{Zone: zone, Keys: []*dns.DNSKEY{parentKSK}}, NewDNSSECValidator(func() time.Time { return nsec3TestNow }))
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion(qname, dns.TypeA)
	req.Message.CheckingDisabled = false
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 1, childDNSKEYQueries)
	require.Equal(t, DNSSECSecure, res.DNSSECStatus)
	require.False(t, res.Message.AuthenticatedData)
	require.False(t, res.Message.CheckingDisabled)
	require.Equal(t, "stub:"+childServer, res.Source)
}

func TestValidatingDelegatingStubResolverCarriesAuthenticatedInsecureChild(t *testing.T) {
	zone := "corp.internal."
	childZone := "legacy.corp.internal."
	qname := "host.legacy.corp.internal."
	rootServer := "192.0.2.20:53"
	childServer := "192.0.2.22:53"

	parentKSK, parentKSKSigner := routedTrustAnchorKey(t, zone, dns.ZONE|dns.SEP)
	parentZSK, parentZSKSigner := routedTrustAnchorKey(t, zone, dns.ZONE)
	parentDNSKEYSig := signRoutedTrustAnchorRRSet(t, []dns.RR{parentKSK, parentZSK}, parentKSK, parentKSKSigner)
	denial := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: childZone, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "next." + zone,
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
	}
	denialSig := signRoutedTrustAnchorRRSet(t, []dns.RR{denial}, parentZSK, parentZSKSigner)
	answer := &dns.A{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{10, 0, 0, 51}}

	var childDNSKEYQueries int
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		require.False(t, query.RecursionDesired)
		require.True(t, query.CheckingDisabled)
		q := query.Question[0]
		reply := new(dns.Msg)
		reply.SetReply(query)
		switch {
		case server == rootServer && q.Qtype == dns.TypeDNSKEY && equalName(q.Name, zone):
			reply.Authoritative = true
			reply.Answer = []dns.RR{parentKSK, parentZSK, parentDNSKEYSig}
			return reply, nil
		case server == rootServer && q.Qtype == dns.TypeA && equalName(q.Name, qname):
			reply.Ns = []dns.RR{
				&dns.NS{Hdr: dns.RR_Header{Name: childZone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns." + childZone},
				denial,
				denialSig,
			}
			reply.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns." + childZone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 22}}}
			return reply, nil
		case server == childServer && q.Qtype == dns.TypeDNSKEY:
			childDNSKEYQueries++
			return nil, errors.New("insecure child DNSKEY must not be queried")
		case server == childServer && q.Qtype == dns.TypeA && equalName(q.Name, qname):
			reply.Authoritative = true
			reply.Answer = []dns.RR{answer}
			return reply, nil
		default:
			return nil, errors.New("unexpected insecure validating stub query")
		}
	})

	resolver, err := NewValidatingDelegatingStubResolver(exchanger, zone, []string{rootServer}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1}, PrivateDNSKEYTrustAnchor{Zone: zone, Keys: []*dns.DNSKEY{parentKSK}}, NewDNSSECValidator(func() time.Time { return nsec3TestNow }))
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion(qname, dns.TypeA)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Zero(t, childDNSKEYQueries)
	require.Equal(t, DNSSECInsecure, res.DNSSECStatus)
}

func TestValidatingDelegatingStubResolverRejectsUnprovenChildDelegation(t *testing.T) {
	zone := "corp.internal."
	childZone := "unproven.corp.internal."
	qname := "host.unproven.corp.internal."
	rootServer := "192.0.2.20:53"
	parentKSK, parentSigner := routedTrustAnchorKey(t, zone, dns.ZONE|dns.SEP)
	parentDNSKEYSig := signRoutedTrustAnchorRRSet(t, []dns.RR{parentKSK}, parentKSK, parentSigner)
	var childQueries int
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		q := query.Question[0]
		reply := new(dns.Msg)
		reply.SetReply(query)
		if server != rootServer {
			childQueries++
			return nil, errors.New("unproven child must not be queried")
		}
		if q.Qtype == dns.TypeDNSKEY {
			reply.Authoritative = true
			reply.Answer = []dns.RR{parentKSK, parentDNSKEYSig}
			return reply, nil
		}
		reply.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: childZone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns." + childZone}}
		reply.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns." + childZone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 23}}}
		return reply, nil
	})
	resolver, err := NewValidatingDelegatingStubResolver(exchanger, zone, []string{rootServer}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1}, PrivateDNSKEYTrustAnchor{Zone: zone, Keys: []*dns.DNSKEY{parentKSK}}, NewDNSSECValidator(func() time.Time { return nsec3TestNow }))
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion(qname, dns.TypeA)
	_, err = resolver.Resolve(context.Background(), req)
	require.ErrorContains(t, err, "lacks authenticated DS or denial proof")
	require.Zero(t, childQueries)
}

func TestValidatingDelegatingStubResolverRejectsAnchorZoneMismatch(t *testing.T) {
	anchor, _ := routedTrustAnchorKey(t, "other.internal.", dns.ZONE|dns.SEP)
	_, err := NewValidatingDelegatingStubResolver(exchangeFunc(func(context.Context, string, *dns.Msg) (*dns.Msg, error) { return nil, nil }), "corp.internal.", []string{"192.0.2.20:53"}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1}, PrivateDNSKEYTrustAnchor{Zone: "other.internal.", Keys: []*dns.DNSKEY{anchor}}, NewDNSSECValidator(nil))
	require.ErrorContains(t, err, "does not match private trust-anchor zone")
}
