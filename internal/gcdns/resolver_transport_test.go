package gcdns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type fakeDNSExchanger struct {
	calls int
	last  *dns.Msg
	resp  *dns.Msg
	err   error
}

func (f *fakeDNSExchanger) ExchangeContext(_ context.Context, msg *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
	f.calls++
	f.last = msg.Copy()
	if f.resp == nil {
		return nil, 0, f.err
	}
	return f.resp.Copy(), time.Millisecond, f.err
}

func transportQuery() *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Id = 1234
	return msg
}

func transportReply(query *dns.Msg) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(query)
	return msg
}

func TestResolverTransportUDP(t *testing.T) {
	query := transportQuery()
	udp := &fakeDNSExchanger{resp: transportReply(query)}
	transport := newResolverTransportWithExchangers(ResolverTransportConfig{AllowTCPFallback: true}, udp, &fakeDNSExchanger{})

	res, err := transport.ResolveTarget(context.Background(), &Request{Message: query}, ResolverTarget{ID: "root-a", Address: "192.0.2.53:53"})
	require.NoError(t, err)
	require.Equal(t, "root-a", res.Source)
	require.Equal(t, 1, udp.calls)
	require.NotSame(t, query, udp.last)
}

func TestResolverTransportTruncatedUDPFallsBackToTCP(t *testing.T) {
	query := transportQuery()
	truncated := transportReply(query)
	truncated.Truncated = true
	complete := transportReply(query)

	udp := &fakeDNSExchanger{resp: truncated}
	tcp := &fakeDNSExchanger{resp: complete}
	transport := newResolverTransportWithExchangers(ResolverTransportConfig{AllowTCPFallback: true}, udp, tcp)

	res, err := transport.ResolveTarget(context.Background(), &Request{Message: query}, ResolverTarget{ID: "root-a", Address: "192.0.2.53:53"})
	require.NoError(t, err)
	require.False(t, res.Message.Truncated)
	require.Equal(t, 1, udp.calls)
	require.Equal(t, 1, tcp.calls)
}

func TestResolverTransportRejectsMismatchedResponse(t *testing.T) {
	query := transportQuery()
	response := transportReply(query)
	response.Id++

	transport := newResolverTransportWithExchangers(ResolverTransportConfig{}, &fakeDNSExchanger{resp: response}, &fakeDNSExchanger{})
	_, err := transport.ResolveTarget(context.Background(), &Request{Message: query}, ResolverTarget{ID: "root-a", Address: "192.0.2.53:53"})
	require.ErrorContains(t, err, "transaction id mismatch")
}

func TestResolverTransportRejectsInvalidTarget(t *testing.T) {
	transport := NewResolverTransport(ResolverTransportConfig{})
	_, err := transport.ResolveTarget(context.Background(), &Request{Message: transportQuery()}, ResolverTarget{ID: "missing-address"})
	require.ErrorContains(t, err, "has no address")

	_, err = transport.ResolveTarget(context.Background(), &Request{Message: transportQuery()}, ResolverTarget{ID: "bad-network", Address: "192.0.2.53:53", Network: "quic"})
	require.ErrorContains(t, err, "unsupported network")
}

func TestResolverTransportPropagatesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	transport := newResolverTransportWithExchangers(ResolverTransportConfig{}, &fakeDNSExchanger{err: errors.New("must not run")}, &fakeDNSExchanger{})
	_, err := transport.ResolveTarget(ctx, &Request{Message: transportQuery()}, ResolverTarget{ID: "root-a", Address: "192.0.2.53:53"})
	require.ErrorIs(t, err, context.Canceled)
}

func TestValidateDNSResponseQuestionMismatch(t *testing.T) {
	query := transportQuery()
	response := transportReply(query)
	response.Question[0].Qtype = dns.TypeAAAA

	err := validateDNSResponse(query, response)
	require.ErrorContains(t, err, "does not match query")
}
