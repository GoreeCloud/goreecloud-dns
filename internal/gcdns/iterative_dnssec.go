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
	return r.resolveWithState(ctx, req, newResolutionState())
}

func (r *ValidatingIterativeResolver) resolveWithState(ctx context.Context, req *Request, state *resolutionState) (*Result, error) {
	if req == nil || req.Message == nil {
		return nil, errors.New("goreecloud dns: validating iterative resolver request is nil")
	}
	if len(req.Message.Question) != 1 {
		return nil, errors.New("goreecloud dns: validating iterative resolver requires exactly one question")
	}
	if result, handled := compactDenialQueryResponse(req); handled {
		return result, nil
	}
	if state == nil {
		state = newResolutionState()
	}

	original := req
	current := req
	seenAliases := map[string]struct{}{dns.CanonicalName(req.Message.Question[0].Name): {}}
	var priorAnswers []dns.RR
	var priorTTL time.Duration
	overallStatus := DNSSECSecure
	haveStatus := false

	for aliasDepth := 0; aliasDepth < maxAliasTransitions; aliasDepth++ {
		res, err := r.resolveSingle(ctx, current, state)
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

func (r *ValidatingIterativeResolver) resolveSingle(ctx context.Context, req *Request, state *resolutionState) (*Result, error) {
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

	q := req.Message.Question[0]
	upstreamReq := requestWithCompactAnswersOK(req)
	servers := append([]string(nil), r.iterative.rootServers...)
	seenDelegations := map[string]struct{}{}
	chainSecure := true
	cursor := "."
	minimise := qnameMinimisationEligible(req)

	for delegations := 0; delegations < r.iterative.maxDepth; {
		if minimise {
			child, more, err := nextMinimisedQNAME(q.Name, cursor)
			if err != nil {
				return nil, err
			}
			if !more || !consumeQNAMEMinimisationBudget(state) {
				minimise = false
			} else {
				probeBase, err := qnameMinimisationProbe(req, child)
				if err != nil {
					return nil, err
				}
				probeReq := requestWithCompactAnswersOK(probeBase)
				probeRes, err := r.iterative.resolveAgainst(ctx, probeReq, servers)
				if err != nil {
					minimise = false
				} else if !terminalDNSResponse(probeRes.Message) {
					servers, parentKeys, chainSecure, cursor, err = r.advanceValidatingReferral(ctx, upstreamReq, probeRes.Message, q.Name, parentKeys, chainSecure, state, seenDelegations)
					if err != nil {
						return nil, err
					}
					delegations++
					continue
				} else if probeRes.Message != nil && (probeRes.Message.Rcode == dns.RcodeSuccess || probeRes.Message.Rcode == dns.RcodeNameError) {
					probeStatus := DNSSECInsecure
					if chainSecure {
						if r.terminal == nil {
							minimise = false
							probeStatus = DNSSECIndeterminate
						} else {
							probeStatus, err = r.terminal.AuthenticateTerminalAnswer(probeRes.Message, parentKeys)
							if err != nil {
								return nil, fmt.Errorf("goreecloud dns: QNAME minimisation DNSSEC authentication failed: %w", err)
							}
							if probeStatus != DNSSECSecure {
								// Do not let unproven minimisation responses influence zone-cut
								// discovery on a secure branch. Use the full original query instead.
								minimise = false
							}
						}
					}

					if sameDNSName(child, q.Name) && q.Qtype == qnameMinimisationQType && (probeStatus == DNSSECSecure || !chainSecure) {
						// The final A minimisation probe is the client's original query.
						// Reuse it after the same trust decision required for an ordinary
						// terminal response instead of sending a duplicate A query.
						probeRes.CacheTTL = responseCacheTTL(probeRes.Message)
						if chainSecure {
							probeRes.DNSSECStatus = DNSSECSecure
							present, responseCO := compactDenialMessageMetadata(probeRes.Message)
							probeRes.CompactDenial = present
							probeRes.CompactDenialCO = present && responseCO
						} else {
							probeRes.DNSSECStatus = DNSSECInsecure
						}
						return probeRes, nil
					}

					if minimise || !chainSecure {
						if probeRes.Message.Rcode == dns.RcodeSuccess && qnameMinimisationResponseHasDNAME(probeRes.Message) {
							minimise = false
						} else {
							// NOERROR (including NODATA/CNAME) and NXDOMAIN continue to
							// expose the next label. Beacon does not yet apply RFC 8020 cuts.
							cursor = child
							continue
						}
					}
				} else {
					minimise = false
				}
			}
		}

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

		servers, parentKeys, chainSecure, cursor, err = r.advanceValidatingReferral(ctx, upstreamReq, res.Message, q.Name, parentKeys, chainSecure, state, seenDelegations)
		if err != nil {
			return nil, err
		}
		delegations++
	}
	return nil, errors.New("goreecloud dns: validating iterative resolver delegation depth exceeded")
}

func (r *ValidatingIterativeResolver) advanceValidatingReferral(ctx context.Context, req *Request, response *dns.Msg, qname string, parentKeys []*dns.DNSKEY, chainSecure bool, state *resolutionState, seenDelegations map[string]struct{}) ([]string, []*dns.DNSKEY, bool, string, error) {
	plan, err := buildReferralPlan(response, qname)
	if err != nil {
		return nil, nil, chainSecure, "", err
	}

	var childDS []*dns.DS
	if chainSecure {
		var status DNSSECStatus
		var authErr error
		childDS, status, authErr = r.chain.AuthenticateDelegationDS(plan.zone, response, parentKeys)
		if authErr != nil {
			return nil, nil, chainSecure, "", fmt.Errorf("goreecloud dns: DNSSEC delegation authentication failed: %w", authErr)
		}
		switch status {
		case DNSSECInsecure:
			chainSecure = false
			parentKeys = nil
		case DNSSECSecure:
			// Authenticate the child DNSKEY RRset after authoritative server
			// addresses are available.
		case DNSSECIndeterminate:
			return nil, nil, chainSecure, "", fmt.Errorf("goreecloud dns: DNSSEC delegation authentication failed: delegation for %s lacks authenticated DS or denial proof", dns.Fqdn(plan.zone))
		default:
			return nil, nil, chainSecure, "", fmt.Errorf("goreecloud dns: DNSSEC delegation authentication failed: delegation for %s is %s", dns.Fqdn(plan.zone), status)
		}
	}

	nextServers, err := completeReferralServers(ctx, req, plan, state, r.resolveWithState)
	if err != nil {
		return nil, nil, chainSecure, "", err
	}
	key := delegationKey(plan.zone, nextServers)
	if _, exists := seenDelegations[key]; exists {
		return nil, nil, chainSecure, "", fmt.Errorf("goreecloud dns: delegation loop detected at %s", plan.zone)
	}
	seenDelegations[key] = struct{}{}

	if !chainSecure {
		return nextServers, nil, false, plan.zone, nil
	}

	childDNSKEY, err := r.resolveDNSKEY(ctx, plan.zone, nextServers)
	if err != nil {
		return nil, nil, chainSecure, "", fmt.Errorf("goreecloud dns: DNSKEY acquisition for %s failed: %w", dns.Fqdn(plan.zone), err)
	}
	childKeys, status, err := r.chain.AuthenticateDNSKEYResponse(plan.zone, childDNSKEY, childDS)
	if err != nil || status != DNSSECSecure {
		if err == nil {
			err = fmt.Errorf("DNSKEY RRset for %s did not establish secure trust", dns.Fqdn(plan.zone))
		}
		return nil, nil, chainSecure, "", fmt.Errorf("goreecloud dns: child DNSSEC authentication failed: %w", err)
	}
	return nextServers, childKeys, true, plan.zone, nil
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
