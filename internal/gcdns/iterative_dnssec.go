package gcdns

import (
	"context"
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// DNSSECChainAuthenticator is the trust-chain boundary used by the validating
// iterative resolver. DNSSECValidator implements this interface; keeping the
// boundary injectable allows deterministic delegation tests without weakening
// the production validation rules.
type DNSSECChainAuthenticator interface {
	AuthenticateDNSKEYResponse(zone string, msg *dns.Msg, parentDS []*dns.DS) ([]*dns.DNSKEY, DNSSECStatus, error)
	AuthenticateDelegationDS(childZone string, msg *dns.Msg, parentKeys []*dns.DNSKEY) ([]*dns.DS, DNSSECStatus, error)
}

// ValidatingIterativeResolver carries authenticated DNSSEC key state through
// each secure delegation. It intentionally does not mark terminal answers
// secure until terminal RRset validation and authenticated denial are wired.
type ValidatingIterativeResolver struct {
	iterative *IterativeResolver
	chain     DNSSECChainAuthenticator
}

func NewValidatingIterativeResolver(exchanger DNSExchanger, cfg IterativeResolverConfig, chain DNSSECChainAuthenticator) (*ValidatingIterativeResolver, error) {
	if chain == nil {
		return nil, errors.New("goreecloud dns: validating iterative resolver requires a DNSSEC chain authenticator")
	}
	iterative, err := NewIterativeResolver(exchanger, cfg)
	if err != nil {
		return nil, err
	}
	return &ValidatingIterativeResolver{iterative: iterative, chain: chain}, nil
}

func (r *ValidatingIterativeResolver) Resolve(ctx context.Context, req *Request) (*Result, error) {
	if req == nil || req.Message == nil {
		return nil, errors.New("goreecloud dns: validating iterative resolver request is nil")
	}
	if len(req.Message.Question) != 1 {
		return nil, errors.New("goreecloud dns: validating iterative resolver requires exactly one question")
	}

	rootDNSKEY, err := r.resolveDNSKEY(ctx, ".", r.iterative.rootServers)
	if err != nil {
		return nil, fmt.Errorf("goreecloud dns: root DNSKEY acquisition failed: %w", err)
	}
	parentKeys, status, err := r.chain.AuthenticateDNSKEYResponse(".", rootDNSKEY, RootTrustAnchors())
	if err != nil || status != DNSSECSecure {
		if err == nil {
			err = errors.New("root DNSKEY RRset did not establish secure trust")
		}
		return nil, fmt.Errorf("goreecloud dns: root DNSSEC authentication failed: %w", err)
	}

	servers := append([]string(nil), r.iterative.rootServers...)
	seenDelegations := map[string]struct{}{}
	for depth := 0; depth < r.iterative.maxDepth; depth++ {
		res, err := r.iterative.resolveAgainst(ctx, req, servers)
		if err != nil {
			return nil, err
		}
		if terminalDNSResponse(res.Message) {
			res.CacheTTL = responseCacheTTL(res.Message)
			// Delegation trust has been established to the answering zone, but the
			// answer RRset itself has not yet been validated here.
			res.DNSSECStatus = DNSSECIndeterminate
			return res, nil
		}

		zone, nextServers, err := referralTargets(res.Message, req.Message.Question[0].Name)
		if err != nil {
			return nil, err
		}
		key := delegationKey(zone, nextServers)
		if _, exists := seenDelegations[key]; exists {
			return nil, fmt.Errorf("goreecloud dns: delegation loop detected at %s", zone)
		}
		seenDelegations[key] = struct{}{}

		childDS, status, err := r.chain.AuthenticateDelegationDS(zone, res.Message, parentKeys)
		if err != nil || status != DNSSECSecure {
			if err == nil {
				err = fmt.Errorf("delegation for %s cannot be classified secure without authenticated denial support", dns.Fqdn(zone))
			}
			return nil, fmt.Errorf("goreecloud dns: DNSSEC delegation authentication failed: %w", err)
		}

		childDNSKEY, err := r.resolveDNSKEY(ctx, zone, nextServers)
		if err != nil {
			return nil, fmt.Errorf("goreecloud dns: DNSKEY acquisition for %s failed: %w", dns.Fqdn(zone), err)
		}
		childKeys, status, err := r.chain.AuthenticateDNSKEYResponse(zone, childDNSKEY, childDS)
		if err != nil || status != DNSSECSecure {
			if err == nil {
				err = fmt.Errorf("DNSKEY RRset for %s did not establish secure trust", dns.Fqdn(zone))
			}
			return nil, fmt.Errorf("goreecloud dns: child DNSSEC authentication failed: %w", err)
		}

		parentKeys = childKeys
		servers = nextServers
	}
	return nil, errors.New("goreecloud dns: validating iterative resolver delegation depth exceeded")
}

func (r *ValidatingIterativeResolver) resolveDNSKEY(ctx context.Context, zone string, servers []string) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(zone), dns.TypeDNSKEY)
	req := &Request{Message: msg, Transport: TransportDNS}
	res, err := r.iterative.resolveAgainst(ctx, req, servers)
	if err != nil {
		return nil, err
	}
	if res == nil || res.Message == nil {
		return nil, errors.New("goreecloud dns: DNSKEY query returned no DNS message")
	}
	return res.Message, nil
}

var _ Resolver = (*ValidatingIterativeResolver)(nil)
