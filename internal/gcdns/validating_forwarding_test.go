package gcdns

import (
	"context"
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func forwardingTestKey(t *testing.T, zone string) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	return routedTrustAnchorKey(t, zone, dns.ZONE|dns.SEP)
}

func forwardingSignedReply(t *testing.T, query *dns.Msg, rrset []dns.RR, key *dns.DNSKEY, signer crypto.Signer) *dns.Msg {
	t.Helper()
	reply := new(dns.Msg)
	reply.SetReply(query)
	reply.AuthenticatedData = true
	if len(rrset) != 0 {
		reply.Answer = append(reply.Answer, rrset...)
		reply.Answer = append(reply.Answer, signRoutedTrustAnchorRRSet(t, rrset, key, signer))
	}
	return reply
}

func forwardingNSECReply(t *testing.T, query *dns.Msg, owner string, bitmap []uint16, key *dns.DNSKEY, signer crypto.Signer) *dns.Msg {
	t.Helper()
	reply := new(dns.Msg)
	reply.SetReply(query)
	reply.AuthenticatedData = true
	nsec := &dns.NSEC{
		Hdr:         dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain:  "zzz." + dns.Fqdn(parentDNSName(owner)),
		TypeBitMap: append([]uint16(nil), bitmap...),
	}
	sig := signRoutedTrustAnchorRRSet(t, []dns.RR{nsec}, key, signer)
	reply.Ns = []dns.RR{nsec, sig}
	return reply
}

func newTestValidatingForwarder(t *testing.T, exchanger DNSExchanger, rootAnchor *dns.DS) *ValidatingForwardingResolver {
	t.Helper()
	resolver, err := newValidatingForwardingResolver(
		exchanger,
		[]string{"192.0.2.53:53"},
		SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1},
		NewDNSSECValidator(func() time.Time { return nsec3TestNow }),
		[]*dns.DS{rootAnchor},
	)
	require.NoError(t, err)
	return resolver
}

func TestValidatingForwardingResolverAuthenticatesSecureAnswer(t *testing.T) {
	rootKey, rootSigner := forwardingTestKey(t, ".")
	rootAnchor := rootKey.ToDS(dns.SHA256)
	testKey, testSigner := forwardingTestKey(t, "test.")
	testDS := testKey.ToDS(dns.SHA256)
	answer := &dns.A{Hdr: dns.RR_Header{Name: "host.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{192, 0, 2, 80}}

	var calls int
	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		calls++
		require.Equal(t, "192.0.2.53:53", server)
		require.True(t, query.RecursionDesired)
		require.True(t, query.CheckingDisabled)
		require.NotNil(t, query.IsEdns0())
		require.True(t, query.IsEdns0().Do())
		q := query.Question[0]
		switch {
		case q.Qtype == dns.TypeA && sameDNSName(q.Name, "host.test."):
			return forwardingSignedReply(t, query, []dns.RR{answer}, testKey, testSigner), nil
		case q.Qtype == dns.TypeDNSKEY && sameDNSName(q.Name, "."):
			return forwardingSignedReply(t, query, []dns.RR{rootKey}, rootKey, rootSigner), nil
		case q.Qtype == dns.TypeDS && sameDNSName(q.Name, "test."):
			return forwardingSignedReply(t, query, []dns.RR{testDS}, rootKey, rootSigner), nil
		case q.Qtype == dns.TypeDNSKEY && sameDNSName(q.Name, "test."):
			return forwardingSignedReply(t, query, []dns.RR{testKey}, testKey, testSigner), nil
		default:
			return nil, errors.New("unexpected validating forwarding query")
		}
	})

	resolver := newTestValidatingForwarder(t, exchanger, rootAnchor)
	req := testRequest()
	req.Message.SetQuestion("host.test.", dns.TypeA)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 4, calls)
	require.Equal(t, DNSSECSecure, res.DNSSECStatus)
	require.False(t, res.Message.AuthenticatedData)
	require.False(t, res.Message.CheckingDisabled)
	require.Equal(t, 60*time.Second, res.CacheTTL)
}

func TestValidatingForwardingResolverCarriesAuthenticatedInsecureDelegation(t *testing.T) {
	rootKey, rootSigner := forwardingTestKey(t, ".")
	rootAnchor := rootKey.ToDS(dns.SHA256)
	testKey, testSigner := forwardingTestKey(t, "test.")
	testDS := testKey.ToDS(dns.SHA256)
	answer := &dns.A{Hdr: dns.RR_Header{Name: "host.unsigned.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: []byte{192, 0, 2, 81}}

	var calls int
	exchanger := exchangeFunc(func(_ context.Context, _ string, query *dns.Msg) (*dns.Msg, error) {
		calls++
		require.True(t, query.CheckingDisabled)
		q := query.Question[0]
		switch {
		case q.Qtype == dns.TypeA && sameDNSName(q.Name, "host.unsigned.test."):
			reply := new(dns.Msg)
			reply.SetReply(query)
			reply.AuthenticatedData = true
			reply.Answer = []dns.RR{answer}
			return reply, nil
		case q.Qtype == dns.TypeDNSKEY && sameDNSName(q.Name, "."):
			return forwardingSignedReply(t, query, []dns.RR{rootKey}, rootKey, rootSigner), nil
		case q.Qtype == dns.TypeDS && sameDNSName(q.Name, "test."):
			return forwardingSignedReply(t, query, []dns.RR{testDS}, rootKey, rootSigner), nil
		case q.Qtype == dns.TypeDNSKEY && sameDNSName(q.Name, "test."):
			return forwardingSignedReply(t, query, []dns.RR{testKey}, testKey, testSigner), nil
		case q.Qtype == dns.TypeDS && sameDNSName(q.Name, "unsigned.test."):
			return forwardingNSECReply(t, query, "unsigned.test.", []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC}, testKey, testSigner), nil
		default:
			return nil, errors.New("unexpected query after insecure delegation")
		}
	})

	resolver := newTestValidatingForwarder(t, exchanger, rootAnchor)
	req := testRequest()
	req.Message.SetQuestion("host.unsigned.test.", dns.TypeA)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 5, calls)
	require.Equal(t, DNSSECInsecure, res.DNSSECStatus)
	require.False(t, res.Message.AuthenticatedData)
}

func TestValidatingForwardingResolverRejectsUnclassifiedIntermediateDSState(t *testing.T) {
	rootKey, rootSigner := forwardingTestKey(t, ".")
	rootAnchor := rootKey.ToDS(dns.SHA256)
	testKey, testSigner := forwardingTestKey(t, "test.")
	testDS := testKey.ToDS(dns.SHA256)
	childKey, childSigner := forwardingTestKey(t, "child.deep.test.")
	answer := &dns.A{Hdr: dns.RR_Header{Name: "host.child.deep.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{192, 0, 2, 82}}

	exchanger := exchangeFunc(func(_ context.Context, _ string, query *dns.Msg) (*dns.Msg, error) {
		q := query.Question[0]
		switch {
		case q.Qtype == dns.TypeA && sameDNSName(q.Name, "host.child.deep.test."):
			return forwardingSignedReply(t, query, []dns.RR{answer}, childKey, childSigner), nil
		case q.Qtype == dns.TypeDNSKEY && sameDNSName(q.Name, "."):
			return forwardingSignedReply(t, query, []dns.RR{rootKey}, rootKey, rootSigner), nil
		case q.Qtype == dns.TypeDS && sameDNSName(q.Name, "test."):
			return forwardingSignedReply(t, query, []dns.RR{testDS}, rootKey, rootSigner), nil
		case q.Qtype == dns.TypeDNSKEY && sameDNSName(q.Name, "test."):
			return forwardingSignedReply(t, query, []dns.RR{testKey}, testKey, testSigner), nil
		case q.Qtype == dns.TypeDS && sameDNSName(q.Name, "deep.test."):
			reply := new(dns.Msg)
			reply.SetReply(query)
			return reply, nil
		default:
			return nil, errors.New("unexpected validating forwarding query")
		}
	})

	resolver := newTestValidatingForwarder(t, exchanger, rootAnchor)
	req := testRequest()
	req.Message.SetQuestion("host.child.deep.test.", dns.TypeA)
	_, err := resolver.Resolve(context.Background(), req)
	require.ErrorContains(t, err, "cannot classify DS state for deep.test.")
}

func TestValidatingForwardingResolverRejectsInvalidConstruction(t *testing.T) {
	cfg := SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1}
	exchanger := exchangeFunc(func(context.Context, string, *dns.Msg) (*dns.Msg, error) { return nil, nil })
	_, err := newValidatingForwardingResolver(exchanger, []string{"192.0.2.53:53"}, cfg, nil, RootTrustAnchors())
	require.ErrorContains(t, err, "requires a DNSSEC validator")
	_, err = newValidatingForwardingResolver(exchanger, []string{"192.0.2.53:53"}, cfg, NewDNSSECValidator(nil), nil)
	require.ErrorContains(t, err, "requires at least one root DS trust anchor")
	badAnchor := &dns.DS{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeDS, Class: dns.ClassINET}}
	_, err = newValidatingForwardingResolver(exchanger, []string{"192.0.2.53:53"}, cfg, NewDNSSECValidator(nil), []*dns.DS{badAnchor})
	require.ErrorContains(t, err, "invalid root DS trust anchor")
}

func TestForwardingValidationCandidatesWalkRootOutward(t *testing.T) {
	candidates, err := forwardingValidationCandidates("www.example.test.")
	require.NoError(t, err)
	require.Equal(t, []string{"test.", "example.test.", "www.example.test."}, candidates)
}
