package gcdns

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func compactDenialCOResponse(t *testing.T, rcode int, co bool) (*dns.Msg, *dns.DNSKEY) {
	t.Helper()
	qname := "missing.example.test."
	record, sig, key := compactDenialTestNSEC(t, qname, []uint16{dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNXNAME})
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeAAAA)
	msg.Rcode = rcode
	msg.Ns = []dns.RR{record, sig}
	msg.SetEdns0(1232, true)
	msg.IsEdns0().SetCo(co)
	return msg, key
}

func TestAuthenticateCompactDenialAcceptsSignaledNXDOMAIN(t *testing.T) {
	msg, key := compactDenialCOResponse(t, dns.RcodeNameError, true)
	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, handled, err := validator.AuthenticateCompactDenial(msg, "missing.example.test.", []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.True(t, handled)
	require.Equal(t, DNSSECSecure, status)
}

func TestAuthenticateCompactDenialRejectsNXDOMAINWithoutCO(t *testing.T) {
	msg, key := compactDenialCOResponse(t, dns.RcodeNameError, false)
	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, handled, err := validator.AuthenticateCompactDenial(msg, "missing.example.test.", []*dns.DNSKEY{key})
	require.ErrorContains(t, err, "without the RFC 9824 CO response flag")
	require.True(t, handled)
	require.Equal(t, DNSSECBogus, status)
}

func TestExchangeResolverSignalsCompactAnswersOK(t *testing.T) {
	var captured *dns.Msg
	exchanger := exchangeFunc(func(_ context.Context, _ string, query *dns.Msg) (*dns.Msg, error) {
		captured = query.Copy()
		reply := new(dns.Msg)
		reply.SetReply(query)
		return reply, nil
	})
	query := new(dns.Msg)
	query.SetQuestion("example.test.", dns.TypeA)
	resolver := &exchangeResolver{server: "192.0.2.53:53", exchanger: exchanger}
	_, err := resolver.Resolve(context.Background(), &Request{Message: query, Transport: TransportDNS, CompactAnswersOK: true})
	require.NoError(t, err)
	require.NotNil(t, captured)
	require.NotNil(t, captured.IsEdns0())
	require.True(t, captured.IsEdns0().Do())
	require.True(t, captured.IsEdns0().Co())
}

func TestExchangeResolverDoesNotSignalCOWithoutCapability(t *testing.T) {
	var captured *dns.Msg
	exchanger := exchangeFunc(func(_ context.Context, _ string, query *dns.Msg) (*dns.Msg, error) {
		captured = query.Copy()
		reply := new(dns.Msg)
		reply.SetReply(query)
		return reply, nil
	})
	query := new(dns.Msg)
	query.SetQuestion("example.test.", dns.TypeA)
	resolver := &exchangeResolver{server: "192.0.2.53:53", exchanger: exchanger}
	_, err := resolver.Resolve(context.Background(), &Request{Message: query, Transport: TransportDNS})
	require.NoError(t, err)
	require.NotNil(t, captured)
	require.NotNil(t, captured.IsEdns0())
	require.True(t, captured.IsEdns0().Do())
	require.False(t, captured.IsEdns0().Co())
}

func compactClientRequest(do, co bool) *Request {
	msg := new(dns.Msg)
	msg.SetQuestion("missing.example.test.", dns.TypeAAAA)
	msg.SetEdns0(1232, do)
	msg.IsEdns0().SetCo(co)
	return &Request{Message: msg, Transport: TransportDNS}
}

func compactClientRequestWithoutEDNS() *Request {
	msg := new(dns.Msg)
	msg.SetQuestion("missing.example.test.", dns.TypeAAAA)
	return &Request{Message: msg, Transport: TransportDNS}
}

func compactCachedResult(t *testing.T) *Result {
	t.Helper()
	msg, _ := compactDenialCOResponse(t, dns.RcodeNameError, true)
	return &Result{
		Message:         msg,
		Source:          "resolver",
		CacheTTL:        time.Minute,
		DNSSECStatus:    DNSSECSecure,
		CompactDenial:   true,
		CompactDenialCO: true,
	}
}

func TestPrepareCompactDenialForDNSSECClientWithoutCO(t *testing.T) {
	cached := compactCachedResult(t)
	out := prepareCompactDenialForClient(compactClientRequest(true, false), cached)
	require.Equal(t, dns.RcodeSuccess, out.Message.Rcode)
	require.True(t, out.Message.IsEdns0().Do())
	require.False(t, out.Message.IsEdns0().Co())
	require.Len(t, out.Message.Ns, 2)
	require.True(t, out.CompactDenial)
	require.True(t, out.CompactDenialCO)
	require.Equal(t, dns.RcodeNameError, cached.Message.Rcode)
	require.True(t, cached.Message.IsEdns0().Co())
}

func TestPrepareCompactDenialForCOClient(t *testing.T) {
	out := prepareCompactDenialForClient(compactClientRequest(true, true), compactCachedResult(t))
	require.Equal(t, dns.RcodeNameError, out.Message.Rcode)
	require.True(t, out.Message.IsEdns0().Do())
	require.True(t, out.Message.IsEdns0().Co())
	require.Len(t, out.Message.Ns, 2)
}

func TestPrepareCompactDenialForNonDOClient(t *testing.T) {
	out := prepareCompactDenialForClient(compactClientRequest(false, false), compactCachedResult(t))
	require.Equal(t, dns.RcodeNameError, out.Message.Rcode)
	require.NotNil(t, out.Message.IsEdns0())
	require.False(t, out.Message.IsEdns0().Do())
	require.False(t, out.Message.IsEdns0().Co())
	require.Empty(t, out.Message.Ns)
}

func TestPrepareCompactDenialForClientWithoutEDNS(t *testing.T) {
	out := prepareCompactDenialForClient(compactClientRequestWithoutEDNS(), compactCachedResult(t))
	require.Equal(t, dns.RcodeNameError, out.Message.Rcode)
	require.Nil(t, out.Message.IsEdns0())
	require.Empty(t, out.Message.Ns)
}

func TestCompactDenialMessageMetadata(t *testing.T) {
	msg, _ := compactDenialCOResponse(t, dns.RcodeNameError, true)
	present, responseCO := compactDenialMessageMetadata(msg)
	require.True(t, present)
	require.True(t, responseCO)
}

func TestMemoryCachePreservesCompactDenialMetadata(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cache, err := NewMemoryCache(MemoryCacheConfig{Shards: 1, MaxEntries: 4, Now: func() time.Time { return now }})
	require.NoError(t, err)
	req := compactClientRequest(true, true)
	res := compactCachedResult(t)
	require.NoError(t, cache.Put(context.Background(), req, res, time.Minute))
	got, ok, err := cache.Get(context.Background(), req)
	require.NoError(t, err)
	require.True(t, ok)
	require.True(t, got.CompactDenial)
	require.True(t, got.CompactDenialCO)
}

func TestPipelineRestoresCachedCompactDenialPerClient(t *testing.T) {
	cached := compactCachedResult(t)
	cache := &cacheStub{result: cached, ok: true}
	p := &Pipeline{
		Policy: passPolicy(), Authority: passAuthority(), Cache: cache,
		Resolver: resolverFunc(func(context.Context, *Request) (*Result, error) {
			t.Fatal("resolver must not run on compact-denial cache hit")
			return nil, nil
		}),
	}
	got, err := p.Resolve(context.Background(), compactClientRequest(true, false))
	require.NoError(t, err)
	require.Equal(t, dns.RcodeSuccess, got.Message.Rcode)
	require.False(t, got.Message.IsEdns0().Co())
	require.Equal(t, dns.RcodeNameError, cached.Message.Rcode)
	require.True(t, cached.Message.IsEdns0().Co())
}
