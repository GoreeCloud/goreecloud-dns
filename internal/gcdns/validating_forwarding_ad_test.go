package gcdns

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestValidatingForwardingResolverIgnoresUpstreamADOnUnsignedSecureBranch(t *testing.T) {
	rootKey, rootSigner := forwardingTestKey(t, ".")
	rootAnchor := rootKey.ToDS(dns.SHA256)
	testKey, testSigner := forwardingTestKey(t, "test.")
	testDS := testKey.ToDS(dns.SHA256)
	answer := &dns.A{Hdr: dns.RR_Header{Name: "host.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{192, 0, 2, 85}}

	exchanger := exchangeFunc(func(_ context.Context, _ string, query *dns.Msg) (*dns.Msg, error) {
		q := query.Question[0]
		switch {
		case q.Qtype == dns.TypeA && sameDNSName(q.Name, "host.test."):
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
		case q.Qtype == dns.TypeDS && sameDNSName(q.Name, "host.test."):
			return forwardingNSECReply(t, query, "host.test.", []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC}, testKey, testSigner), nil
		default:
			return nil, errors.New("unexpected validating forwarding AD query")
		}
	})

	resolver := newTestValidatingForwarder(t, exchanger, rootAnchor)
	req := testRequest()
	req.Message.SetQuestion("host.test.", dns.TypeA)
	_, err := resolver.Resolve(context.Background(), req)
	require.Error(t, err)
	require.ErrorContains(t, err, "terminal DNSSEC authentication failed")
}
