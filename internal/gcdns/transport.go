package gcdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// ClassicTransportConfig controls native DNS exchanges over UDP/TCP.
type ClassicTransportConfig struct {
	Timeout         time.Duration
	MaxResponseSize uint16
}

// TransportStats is a privacy-safe snapshot of classic DNS transport health.
type TransportStats struct {
	Exchanges    uint64
	UDPSuccesses uint64
	TCPFallbacks uint64
	TCPSuccesses uint64
	Failures     uint64
	Timeouts     uint64
}

// ClassicTransport performs classic DNS exchanges and retries truncated UDP
// replies over TCP. It validates response identity and question echoing before
// returning a DNS message to the resolver layer.
type ClassicTransport struct {
	timeout      time.Duration
	udp          *dns.Client
	tcp          *dns.Client
	exchanges    atomic.Uint64
	udpSuccesses atomic.Uint64
	tcpFallbacks atomic.Uint64
	tcpSuccesses atomic.Uint64
	failures     atomic.Uint64
	timeouts     atomic.Uint64
}

func NewClassicTransport(cfg ClassicTransportConfig) (*ClassicTransport, error) {
	if cfg.Timeout <= 0 {
		return nil, errors.New("goreecloud dns: transport timeout must be positive")
	}
	if cfg.MaxResponseSize == 0 {
		cfg.MaxResponseSize = 4096
	}
	if cfg.MaxResponseSize < 512 {
		return nil, errors.New("goreecloud dns: max response size must be at least 512 bytes")
	}
	return &ClassicTransport{
		timeout: cfg.Timeout,
		udp:     &dns.Client{Net: "udp", Timeout: cfg.Timeout, UDPSize: cfg.MaxResponseSize},
		tcp:     &dns.Client{Net: "tcp", Timeout: cfg.Timeout},
	}, nil
}

// Exchange sends msg to a host:port DNS server. UDP is attempted first; a
// truncated valid UDP response is retried over TCP.
func (t *ClassicTransport) Exchange(ctx context.Context, server string, msg *dns.Msg) (*dns.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if msg == nil {
		return nil, errors.New("goreecloud dns: transport request is nil")
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		return nil, fmt.Errorf("goreecloud dns: invalid DNS server address: %w", err)
	}
	t.exchanges.Add(1)

	udpReply, err := t.exchange(ctx, t.udp, server, msg)
	if err != nil {
		t.recordFailure(ctx, err)
		return nil, err
	}
	if validateErr := validateDNSReply(msg, udpReply); validateErr != nil {
		t.failures.Add(1)
		return nil, validateErr
	}
	if !udpReply.Truncated {
		t.udpSuccesses.Add(1)
		return udpReply, nil
	}

	t.tcpFallbacks.Add(1)
	tcpReply, err := t.exchange(ctx, t.tcp, server, msg)
	if err != nil {
		t.recordFailure(ctx, err)
		return nil, err
	}
	if validateErr := validateDNSReply(msg, tcpReply); validateErr != nil {
		t.failures.Add(1)
		return nil, validateErr
	}
	if tcpReply.Truncated {
		t.failures.Add(1)
		return nil, errors.New("goreecloud dns: truncated TCP DNS response")
	}
	t.tcpSuccesses.Add(1)
	return tcpReply, nil
}

func (t *ClassicTransport) exchange(ctx context.Context, client *dns.Client, server string, msg *dns.Msg) (*dns.Msg, error) {
	exchangeCtx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	reply, _, err := client.ExchangeContext(exchangeCtx, msg.Copy(), server)
	if err != nil {
		return nil, err
	}
	if reply == nil {
		return nil, errors.New("goreecloud dns: transport returned nil response")
	}
	return reply, nil
}

func (t *ClassicTransport) recordFailure(ctx context.Context, err error) {
	t.failures.Add(1)
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) || isTimeout(err) {
		t.timeouts.Add(1)
	}
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func validateDNSReply(req, reply *dns.Msg) error {
	if reply == nil {
		return errors.New("goreecloud dns: nil DNS response")
	}
	if !reply.Response {
		return errors.New("goreecloud dns: received DNS message without response bit")
	}
	if reply.Id != req.Id {
		return errors.New("goreecloud dns: DNS response ID mismatch")
	}
	if reply.Opcode != req.Opcode {
		return errors.New("goreecloud dns: DNS response opcode mismatch")
	}
	if len(reply.Question) != len(req.Question) {
		return errors.New("goreecloud dns: DNS response question count mismatch")
	}
	for i := range req.Question {
		a, b := req.Question[i], reply.Question[i]
		if _, ok := dns.IsDomainName(a.Name); !ok {
			return errors.New("goreecloud dns: malformed request question name")
		}
		if _, ok := dns.IsDomainName(b.Name); !ok {
			return errors.New("goreecloud dns: malformed response question name")
		}
		if !equalName(a.Name, b.Name) || a.Qtype != b.Qtype || a.Qclass != b.Qclass {
			return errors.New("goreecloud dns: DNS response question mismatch")
		}
	}
	return nil
}

func equalName(a, b string) bool {
	return strings.EqualFold(dns.Fqdn(a), dns.Fqdn(b))
}

func (t *ClassicTransport) Stats() TransportStats {
	return TransportStats{
		Exchanges:    t.exchanges.Load(),
		UDPSuccesses: t.udpSuccesses.Load(),
		TCPFallbacks: t.tcpFallbacks.Load(),
		TCPSuccesses: t.tcpSuccesses.Load(),
		Failures:     t.failures.Load(),
		Timeouts:     t.timeouts.Load(),
	}
}
