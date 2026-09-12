package gcdns

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestValidatingForwardingResolverRequeriesAliasTarget(t *testing.T) {
	rootKey, rootSigner := forwardingTestKey(t, ".")
	rootAnchor := rootKey.ToDS(dns.SHA256)
	testKey, testSigner := forwardingTestKey(t, "test.")
	testDS := testKey.ToDS(dns.SHA256)
	cname := &dns.CNAME{Hdr: dns.RR_Header{Name: "alias.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "target.test."}
	cnameSig := signRoutedTrustAnchorRRSet(t, []dns.RR{cname}, testKey, testSigner)
	target := &dns.A{Hdr: dns.RR_Header{Name: "target.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: []byte{192, 0, 2, 84}}
	targetSig := signRoutedTrustAnchorRRSet(t, []dns.RR{target}, testKey, testSigner)

	var terminalQueries []string
	exchanger := exchangeFunc(func(_ context.Context, _ string, query *dns.Msg) (*dns.Msg, error) {
		q := query.Question[0]
		switch {
		case q.Qtype == dns.TypeA && sameDNSName(q.Name, "alias.test."):
			terminalQueries = append(terminalQueries, dns.Fqdn(q.Name))
			reply := new(dns.Msg)
			reply.SetReply(query)
			reply.AuthenticatedData = true
			// A recursive forwarder may return the complete CNAME chain. Beacon
			// must validate only the source alias with source-zone trust, then
			// issue a fresh validated lookup for the target.
			reply.Answer = []dns.RR{cname, cnameSig, target, targetSig}
			return reply, nil
		case q.Qtype == dns.TypeA && sameDNSName(q.Name, "target.test."):
			terminalQueries = append(terminalQueries, dns.Fqdn(q.Name))
			return forwardingSignedReply(t, query, []dns.RR{target}, testKey, testSigner), nil
		case q.Qtype == dns.TypeDNSKEY && sameDNSName(q.Name, "."):
			return forwardingSignedReply(t, query, []dns.RR{rootKey}, rootKey, rootSigner), nil
		case q.Qtype == dns.TypeDS && sameDNSName(q.Name, "test."):
			return forwardingSignedReply(t, query, []dns.RR{testDS}, rootKey, rootSigner), nil
		case q.Qtype == dns.TypeDNSKEY && sameDNSName(q.Name, "test."):
			return forwardingSignedReply(t, query, []dns.RR{testKey}, testKey, testSigner), nil
		default:
			return nil, errors.New("unexpected validating forwarding alias query")
		}
	})

	resolver := newTestValidatingForwarder(t, exchanger, rootAnchor)
	req := testRequest()
	req.Message.SetQuestion("alias.test.", dns.TypeA)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, []string{"alias.test.", "target.test."}, terminalQueries)
	require.Equal(t, DNSSECSecure, res.DNSSECStatus)
	require.Equal(t, req.Message.Question, res.Message.Question)
	require.True(t, answerHasTypeAt(res.Message, "alias.test.", dns.TypeCNAME))
	require.True(t, answerHasTypeAt(res.Message, "target.test.", dns.TypeA))
}
