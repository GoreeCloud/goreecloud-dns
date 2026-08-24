package gcdns

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

type DNSSECChainAuthenticator interface {
	AuthenticateDNSKEYResponse(zone string, msg *dns.Msg, parentDS []*dns.DS) ([]*dns.DNSKEY, DNSSECStatus, error)
	AuthenticateDelegationDS(childZone string, msg *dns.Msg, parentKeys []*dns.DNSKEY) ([]*dns.DS, DNSSECStatus, error)
}

type DNSSECTerminalAuthenticator interface {
	AuthenticateTerminalAnswer(msg *dns.Msg, keys []*dns.DNSKEY) (DNSSECStatus, error)
}

// ValidatingIterativeResolver carries authenticated DNSSEC state from the root
// through each secure delegation. Once a signed parent denial proves a child is
// intentionally unsigned, the resolver carries DNSSECInsecure for that branch;
// trust is not silently re-established below an insecure delegation.
type ValidatingIterativeResolver struct {
	iterative *IterativeResolver
	chain     DNSSECChainAuthenticator
	terminal  DNSSECTerminalAuthenticator
}

func NewValidatingIterativeResolver(exchanger DNSExchanger, cfg IterativeResolverConfig, chain DNSSECChainAuthenticator) (*ValidatingIterativeResolver, error) {
	if chain == nil {
		return nil, errors.New("goreecloud dns: validating iterative resolver requires a DNSSEC chain authenticator")
	}
	iterative, err := NewIterativeResolver(exchanger, cfg)
	if err != nil {
		return nil, err
	}
	terminal, _ := chain.(DNSSECTerminalAuthenticator)
	return &ValidatingIterativeResolver{iterative: iterative, chain: chain, terminal: terminal}, nil
}

func (r *ValidatingIterativeResolver) Resolve(ctx context.Context, req *Request) (*Result, error) {
	if req == nil || req.Message == nil {
		return nil, errors.New("goreecloud dns: validating iterative resolver request is nil")
	}
	if len(req.Message.Question) != 1 {
		return nil, errors.New("goreecloud dns: validating iterative resolver requires exactly one question")
	}
	if result, handled := compactDenialQueryResponse(req); handled {
		return result, nil
	}

	original := req
	current := req
	seenAliases := map[string]struct{}{dns.CanonicalName(req.Message.Question[0].Name): {}}
	var priorAnswers []dns.RR
	var priorTTL time.Duration
	overallStatus := DNSSECSecure
	haveStatus := false

	for aliasDepth := 0; aliasDepth < maxAliasTransitions; aliasDepth++ {
		res, err := r.resolveSingle(ctx, current)
		if err != nil {
			return nil, err
		}
		if !haveStatus {
			overallStatus = res.DNSSECStatus
			haveStatus = true
		} else {
			overallStatus = combineAliasDNSSEC(overallStatus, res.DNSSECStatus)
		}

		q := current.Message.Question[0]
		target, chase, err := unresolvedAliasTarget(res.Message, q.Name, q.Qtype)
		if err != nil {
			return nil, fmt.Errorf("goreecloud dns: alias-chain processing failed: %w", err)
		}
		if !chase {
			if len(priorAnswers) != 0 && overallStatus == DNSSECIndeterminate {
				return nil, errors.New("goreecloud dns: alias chain ended without a determinate DNSSEC trust state")
			}
			res.DNSSECStatus = overallStatus
			if len(priorAnswers) == 0 {
				return res, nil
			}
			merged, err := mergeAliasResult(original, priorAnswers, priorTTL, res)
			if err != nil {
				return nil, err
			}
			merged.DNSSECStatus = overallStatus
			return merged, nil
		}

		if len(priorAnswers) == 0 || res.CacheTTL < priorTTL {
			priorTTL = res.CacheTTL
		}
		priorAnswers = append(priorAnswers, res.Message.Answer...)
		canonical := dns.CanonicalName(target)
		if _, duplicate := seenAliases[canonical]; duplicate {
			return nil, fmt.Errorf("goreecloud dns: alias loop detected at %s", dns.Fqdn(target))
		}
		seenAliases[canonical] = struct{}{}
		current, err = aliasFollowupRequest(original, target)
		if err != nil {
			return nil, err
		}
	}
	return nil, errors.New("goreecloud dns: alias chain exceeds maximum transition depth")
}

func (r *ValidatingIterativeResolver) resolveSingle(ctx context.Context, req *Request) (*Result, error) {
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

	upstreamReq := requestWithCompactAnswersOK(req)
	servers := append([]string(nil), r.iterative.rootServers...)
	seenDelegations := map[string]struct{}{}
	chainSecure := true
	for depth := 0; depth < r.iterative.maxDepth; depth++ {
		res, err := r.iterative.resolveAgainst(ctx, upstreamReq, servers)
		if err != nil {
			return nil, err
		}
		if terminalDNSResponse(res.Message) {
			res.CacheTTL = responseCacheTTL(res.Message)
			if !chainSecure {
				res.DNSSECStatus = DNSSECInsecure
				return res, nil
			}
			if r.terminal == nil {
				res.DNSSECStatus = DNSSECIndeterminate
				if len(res.Message.Answer) > 0 {
					return nil, errors.New("goreecloud dns: positive terminal answer cannot be accepted without a DNSSEC terminal authenticator")
				}
				return res, nil
			}
			status, err := r.terminal.AuthenticateTerminalAnswer(res.Message, parentKeys)
			if err != nil {
				return nil, fmt.Errorf("goreecloud dns: terminal DNSSEC authentication failed: %w", err)
			}
			res.DNSSECStatus = status
			if status == DNSSECSecure {
				present, responseCO := compactDenialMessageMetadata(res.Message)
				res.CompactDenial = present
				res.CompactDenialCO = present && responseCO
			}
			if len(res.Message.Answer) > 0 && status != DNSSECSecure {
				return nil, errors.New("goreecloud dns: positive terminal answer did not establish secure DNSSEC validation")
			}
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

		if !chainSecure {
			servers = nextServers
			continue
		}

		childDS, status, err := r.chain.AuthenticateDelegationDS(zone, res.Message, parentKeys)
		if err != nil {
			return nil, fmt.Errorf("goreecloud dns: DNSSEC delegation authentication failed: %w", err)
		}
		switch status {
		case DNSSECInsecure:
			// The parent proved that this child is intentionally unsigned. DNSSEC
			// cannot become secure again below this point without another configured
			// trust anchor, so continue resolution while preserving insecure state.
			chainSecure = false
			parentKeys = nil
			servers = nextServers
			continue
		case DNSSECSecure:
			// Continue below and authenticate the child's DNSKEY RRset.
		case DNSSECIndeterminate:
			return nil, fmt.Errorf("goreecloud dns: DNSSEC delegation authentication failed: delegation for %s lacks authenticated DS or denial proof", dns.Fqdn(zone))
		default:
			return nil, fmt.Errorf("goreecloud dns: DNSSEC delegation authentication failed: delegation for %s is %s", dns.Fqdn(zone), status)
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
	req := &Request{Message: msg, Transport: TransportDNS, CompactAnswersOK: true}
	res, err := r.iterative.resolveAgainst(ctx, req, servers)
	if err != nil {
		return nil, err
	}
	if res == nil || res.Message == nil {
		return nil, errors.New("goreecloud dns: DNSKEY query returned no DNS message")
	}
	return res.Message, nil
}

func requestWithCompactAnswersOK(req *Request) *Request {
	if req == nil {
		return nil
	}
	copy := *req
	copy.CompactAnswersOK = true
	return &copy
}

var _ Resolver = (*ValidatingIterativeResolver)(nil)
