package gcdns

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestValidatingForwardingResolverAuthenticatesAcrossNonDelegationLabel(t *testing.T) {
	rootKey, rootSigner := forwardingTestKey(t, ".")
	rootAnchor := rootKey.ToDS(dns.SHA256)
	testKey, testSigner := forwardingTestKey(t, "test.")
	testDS := testKey.ToDS(dns.SHA256)
	childKey, childSigner := forwardingTestKey(t, "child.deep.test.")
	childDS := childKey.ToDS(dns.SHA256)
	answer := &dns.A{Hdr: dns.RR_Header{Name: "host.child.deep.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 45}, A: []byte{192, 0, 2, 83}}

	var calls int
	exchanger := exchangeFunc(func(_ context.Context, _ string, query *dns.Msg) (*dns.Msg, error) {
		calls++
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
			return forwardingNSECReply(t, query, "deep.test.", []uint16{dns.TypeRRSIG, dns.TypeNSEC}, testKey, testSigner), nil
		case q.Qtype == dns.TypeDS && sameDNSName(q.Name, "child.deep.test."):
			return forwardingSignedReply(t, query, []dns.RR{childDS}, testKey, testSigner), nil
		case q.Qtype == dns.TypeDNSKEY && sameDNSName(q.Name, "child.deep.test."):
			return forwardingSignedReply(t, query, []dns.RR{childKey}, childKey, childSigner), nil
		default:
			return nil, errors.New("unexpected validating forwarding query")
		}
	})

	resolver := newTestValidatingForwarder(t, exchanger, rootAnchor)
	req := testRequest()
	req.Message.SetQuestion("host.child.deep.test.", dns.TypeA)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 7, calls)
	require.Equal(t, DNSSECSecure, res.DNSSECStatus)
}
