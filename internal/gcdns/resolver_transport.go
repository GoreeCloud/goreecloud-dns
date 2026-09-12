package gcdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	resolverNetworkUDP = "udp"
	resolverNetworkTCP = "tcp"
)

// DNSExchanger is the narrow transport dependency used by Beacon Resolver.
// dns.Client satisfies this interface and tests may provide deterministic
// implementations without opening network sockets.
type DNSExchanger interface {
	ExchangeContext(ctx context.Context, msg *dns.Msg, address string) (*dns.Msg, time.Duration, error)
}

// ResolverTransportConfig controls classic DNS transport behavior. UDP is the
// preferred transport for normal DNS exchanges and TCP fallback is used for
// truncated UDP responses when enabled.
type ResolverTransportConfig struct {
	AllowTCPFallback bool
}

// ResolverTransport executes classic UDP/TCP DNS exchanges for scheduler
// targets. DNSSEC validation and recursive referral processing intentionally
// remain separate Beacon Resolver responsibilities.
type ResolverTransport struct {
	conf ResolverTransportConfig
	udp  DNSExchanger
	tcp  DNSExchanger
}

// NewResolverTransport creates a Beacon Resolver transport using miekg/dns
// clients. Request lifetimes are controlled by the caller context and the
// ResolverScheduler attempt timeout.
func NewResolverTransport(conf ResolverTransportConfig) *ResolverTransport {
	return newResolverTransportWithExchangers(
		conf,
		&dns.Client{Net: resolverNetworkUDP},
		&dns.Client{Net: resolverNetworkTCP},
	)
}

func newResolverTransportWithExchangers(conf ResolverTransportConfig, udp DNSExchanger, tcp DNSExchanger) *ResolverTransport {
	return &ResolverTransport{conf: conf, udp: udp, tcp: tcp}
}

// ResolveTarget implements TargetResolver.
func (t *ResolverTransport) ResolveTarget(ctx context.Context, req *Request, target ResolverTarget) (*Result, error) {
	if req == nil || req.Message == nil {
		return nil, errors.New("goreecloud dns: nil transport request")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if target.Address == "" {
		return nil, fmt.Errorf("goreecloud dns: resolver target %q has no address", target.ID)
	}
	if _, _, err := net.SplitHostPort(target.Address); err != nil {
		return nil, fmt.Errorf("goreecloud dns: resolver target %q has invalid address: %w", target.ID, err)
	}

	network := strings.ToLower(strings.TrimSpace(target.Network))
	if network == "" {
		network = resolverNetworkUDP
	}

	query := req.Message.Copy()
	switch network {
	case resolverNetworkUDP:
		response, err := t.exchangeAndValidate(ctx, t.udp, query, target)
		if err != nil {
			return nil, err
		}
		if response.Truncated {
			if !t.conf.AllowTCPFallback {
				return nil, fmt.Errorf("goreecloud dns: resolver target %q returned a truncated udp response and tcp fallback is disabled", target.ID)
			}

			response, err = t.exchangeAndValidate(ctx, t.tcp, query, target)
			if err != nil {
				return nil, fmt.Errorf("goreecloud dns: resolver target %q tcp fallback failed: %w", target.ID, err)
			}
			if response.Truncated {
				return nil, fmt.Errorf("goreecloud dns: resolver target %q returned a truncated tcp response", target.ID)
			}
		}

		return &Result{Message: response, Source: target.ID}, nil

	case resolverNetworkTCP:
		response, err := t.exchangeAndValidate(ctx, t.tcp, query, target)
		if err != nil {
			return nil, err
		}
		if response.Truncated {
			return nil, fmt.Errorf("goreecloud dns: resolver target %q returned a truncated tcp response", target.ID)
		}

		return &Result{Message: response, Source: target.ID}, nil

	default:
		return nil, fmt.Errorf("goreecloud dns: resolver target %q uses unsupported network %q", target.ID, target.Network)
	}
}

func (t *ResolverTransport) exchangeAndValidate(ctx context.Context, exchanger DNSExchanger, query *dns.Msg, target ResolverTarget) (*dns.Msg, error) {
	if exchanger == nil {
		return nil, errors.New("goreecloud dns: resolver transport exchanger is unavailable")
	}

	response, _, err := exchanger.ExchangeContext(ctx, query.Copy(), target.Address)
	if err != nil {
		return nil, err
	}
	if err = validateDNSResponse(query, response); err != nil {
		return nil, fmt.Errorf("goreecloud dns: resolver target %q returned an invalid response: %w", target.ID, err)
	}

	return response, nil
}

func validateDNSResponse(query *dns.Msg, response *dns.Msg) error {
	if query == nil {
		return errors.New("nil query")
	}
	if response == nil {
		return errors.New("nil response")
	}
	if !response.Response {
		return errors.New("message is not marked as a response")
	}
	if response.Id != query.Id {
		return fmt.Errorf("transaction id mismatch: got %d want %d", response.Id, query.Id)
	}
	if len(response.Question) != len(query.Question) {
		return fmt.Errorf("question count mismatch: got %d want %d", len(response.Question), len(query.Question))
	}
	for i := range query.Question {
		want := query.Question[i]
		got := response.Question[i]
		if !strings.EqualFold(got.Name, want.Name) || got.Qtype != want.Qtype || got.Qclass != want.Qclass {
			return fmt.Errorf("question %d does not match query", i)
		}
	}

	return nil
}
