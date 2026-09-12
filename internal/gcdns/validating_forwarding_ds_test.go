package gcdns

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestValidatingForwardingResolverValidatesClientDSWithParentKeys(t *testing.T) {
	rootKey, rootSigner := forwardingTestKey(t, ".")
	rootAnchor := rootKey.ToDS(dns.SHA256)
	testKey, _ := forwardingTestKey(t, "test.")
	testDS := testKey.ToDS(dns.SHA256)

	var dnskeyTestQueries int
	exchanger := exchangeFunc(func(_ context.Context, _ string, query *dns.Msg) (*dns.Msg, error) {
		require.True(t, query.CheckingDisabled)
		q := query.Question[0]
		switch {
		case q.Qtype == dns.TypeDS && sameDNSName(q.Name, "test."):
			return forwardingSignedReply(t, query, []dns.RR{testDS}, rootKey, rootSigner), nil
		case q.Qtype == dns.TypeDNSKEY && sameDNSName(q.Name, "."):
			return forwardingSignedReply(t, query, []dns.RR{rootKey}, rootKey, rootSigner), nil
		case q.Qtype == dns.TypeDNSKEY && sameDNSName(q.Name, "test."):
			dnskeyTestQueries++
			return nil, errors.New("client DS validation must not cross into child DNSKEY")
		default:
			return nil, errors.New("unexpected parent-side DS validation query")
		}
	})

	resolver := newTestValidatingForwarder(t, exchanger, rootAnchor)
	req := testRequest()
	req.Message.SetQuestion("test.", dns.TypeDS)
	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 0, dnskeyTestQueries)
	require.Equal(t, DNSSECSecure, res.DNSSECStatus)
	require.False(t, res.Message.AuthenticatedData)
}
