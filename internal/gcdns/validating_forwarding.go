package gcdns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const maxForwardValidationLabels = 128

// ValidatingForwardingResolver uses configured recursive forwarders only as
// transports for DNS data. Beacon establishes the root-to-QNAME DNSSEC trust
// path locally and never treats an upstream AD bit as validation evidence.
type ValidatingForwardingResolver struct {
	forwarder   *ForwardingResolver
	validator   *DNSSECValidator
	rootAnchors []*dns.DS
}

func NewValidatingForwardingResolver(exchanger DNSExchanger, servers []string, cfg SchedulerConfig, validator *DNSSECValidator) (*ValidatingForwardingResolver, error) {
	return newValidatingForwardingResolver(exchanger, servers, cfg, validator, RootTrustAnchors())
}

func newValidatingForwardingResolver(exchanger DNSExchanger, servers []string, cfg SchedulerConfig, validator *DNSSECValidator, rootAnchors []*dns.DS) (*ValidatingForwardingResolver, error) {
	if validator == nil {
		return nil, errors.New("goreecloud dns: validating forwarding resolver requires a DNSSEC validator")
	}
	if len(rootAnchors) == 0 {
		return nil, errors.New("goreecloud dns: validating forwarding resolver requires at least one root DS trust anchor")
	}
	anchors := make([]*dns.DS, 0, len(rootAnchors))
	for _, anchor := range rootAnchors {
		if anchor == nil || !sameDNSName(anchor.Hdr.Name, ".") {
			return nil, errors.New("goreecloud dns: validating forwarding resolver contains an invalid root DS trust anchor")
		}
		copyAnchor := *anchor
		anchors = append(anchors, &copyAnchor)
	}
	forwarder, err := NewForwardingResolver(exchanger, servers, cfg)
	if err != nil {
		return nil, err
	}
	return &ValidatingForwardingResolver{forwarder: forwarder, validator: validator, rootAnchors: anchors}, nil
}

func (r *ValidatingForwardingResolver) Resolve(ctx context.Context, req *Request) (*Result, error) {
	if req == nil || req.Message == nil || len(req.Message.Question) != 1 {
		return nil, errors.New("goreecloud dns: validating forwarding resolver requires exactly one question")
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

	for depth := 0; depth < maxAliasTransitions; depth++ {
		res, target, chase, err := r.resolveSingle(ctx, current)
		if err != nil {
			return nil, err
		}
		if !haveStatus {
			overallStatus = res.DNSSECStatus
			haveStatus = true
		} else {
			overallStatus = combineAliasDNSSEC(overallStatus, res.DNSSECStatus)
		}
		if !chase {
			res.DNSSECStatus = overallStatus
			if len(priorAnswers) == 0 {
				return res, nil
			}
			merged, mergeErr := mergeAliasResult(original, priorAnswers, priorTTL, res)
			if mergeErr != nil {
				return nil, mergeErr
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
			return nil, fmt.Errorf("goreecloud dns: validating forwarding alias loop detected at %s", dns.Fqdn(target))
		}
		seenAliases[canonical] = struct{}{}
		current, err = aliasFollowupRequest(original, target)
		if err != nil {
			return nil, err
		}
	}
	return nil, errors.New("goreecloud dns: validating forwarding alias chain exceeds maximum transition depth")
}

func (r *ValidatingForwardingResolver) resolveSingle(ctx context.Context, req *Request) (*Result, string, bool, error) {
	validationReq := copyRequestForLocalValidation(req)
	validationReq.CompactAnswersOK = true
	res, err := r.forwarder.Resolve(ctx, validationReq)
	if err != nil {
		return nil, "", false, err
	}
	if res == nil || res.Message == nil {
		return nil, "", false, errors.New("goreecloud dns: validating forwarding upstream returned no DNS response")
	}
	res.Message.AuthenticatedData = false

	q := req.Message.Question[0]
	aliasMsg, target, chase, err := forwardingAliasLinkMessage(res.Message, q.Name, q.Qtype)
	if err != nil {
		return nil, "", false, fmt.Errorf("goreecloud dns: validating forwarding alias processing failed: %w", err)
	}
	proofMsg := res.Message
	if chase {
		proofMsg = aliasMsg
	}
	trustName := q.Name
	trustQType := q.Qtype
	if signerZone, present, signerErr := forwardingSignerZone(proofMsg); signerErr != nil {
		return nil, "", false, signerErr
	} else if present {
		// Signed data identifies the authoritative signer zone directly. Walk
		// trust only to that zone rather than probing DS at ordinary owner names,
		// which may themselves be CNAMEs or empty non-terminals.
		trustName = signerZone
		trustQType = dns.TypeDNSKEY
	}
	keys, chainSecure, err := r.authenticateName(ctx, req, trustName, trustQType)
	if err != nil {
		return nil, "", false, err
	}

	if chase {
		if chainSecure {
			aliasStatus, aliasErr := r.validator.AuthenticateTerminalAnswer(aliasMsg, keys)
			if aliasErr != nil {
				return nil, "", false, fmt.Errorf("goreecloud dns: validating forwarding alias DNSSEC authentication failed: %w", aliasErr)
			}
			if aliasStatus != DNSSECSecure {
				return nil, "", false, fmt.Errorf("goreecloud dns: validating forwarding alias response for %s is %s", dns.Fqdn(q.Name), aliasStatus)
			}
			res.DNSSECStatus = DNSSECSecure
		} else {
			res.DNSSECStatus = DNSSECInsecure
		}
		res.Message = aliasMsg
		res.Message.AuthenticatedData = false
		res.Message.CheckingDisabled = req.Message.CheckingDisabled
		res.CacheTTL = responseCacheTTL(aliasMsg)
		return res, target, true, nil
	}

	res.Message.CheckingDisabled = req.Message.CheckingDisabled
	res.CacheTTL = responseCacheTTL(res.Message)
	if !chainSecure {
		res.DNSSECStatus = DNSSECInsecure
		return res, "", false, nil
	}
	status, err := r.validator.AuthenticateTerminalAnswer(res.Message, keys)
	if err != nil {
		return nil, "", false, fmt.Errorf("goreecloud dns: validating forwarding terminal DNSSEC authentication failed: %w", err)
	}
	if status != DNSSECSecure {
		return nil, "", false, fmt.Errorf("goreecloud dns: validating forwarding terminal response for %s is %s", dns.Fqdn(q.Name), status)
	}
	res.DNSSECStatus = DNSSECSecure
	present, responseCO := compactDenialMessageMetadata(res.Message)
	res.CompactDenial = present
	res.CompactDenialCO = present && responseCO
	return res, "", false, nil
}

func (r *ValidatingForwardingResolver) authenticateName(ctx context.Context, original *Request, qname string, qtype uint16) ([]*dns.DNSKEY, bool, error) {
	rootMsg, err := r.queryType(ctx, original, ".", dns.TypeDNSKEY)
	if err != nil {
		return nil, true, fmt.Errorf("goreecloud dns: validating forwarding root DNSKEY acquisition failed: %w", err)
	}
	parentKeys, status, err := r.validator.AuthenticateDNSKEYResponse(".", rootMsg, r.rootAnchors)
	if err != nil || status != DNSSECSecure {
		if err == nil {
			err = fmt.Errorf("root DNSKEY RRset did not establish secure trust: %s", status)
		}
		return nil, true, fmt.Errorf("goreecloud dns: validating forwarding root DNSSEC authentication failed: %w", err)
	}

	candidates, err := forwardingValidationCandidates(qname)
	if err != nil {
		return nil, true, err
	}
	// DS is parent-side data. When the client itself asks for DS at QNAME,
	// validate that terminal RRset with the authenticated parent keys rather
	// than crossing into the child and then attempting to use child DNSKEYs.
	if qtype == dns.TypeDS && len(candidates) != 0 && sameDNSName(candidates[len(candidates)-1], qname) {
		candidates = candidates[:len(candidates)-1]
	}
	for _, candidate := range candidates {
		dsMsg, err := r.queryType(ctx, original, candidate, dns.TypeDS)
		if err != nil {
			return nil, true, fmt.Errorf("goreecloud dns: validating forwarding DS lookup for %s failed: %w", candidate, err)
		}
		childDS, delegationStatus, authErr := r.validator.AuthenticateDelegationDS(candidate, dsMsg, parentKeys)
		if authErr != nil {
			return nil, true, fmt.Errorf("goreecloud dns: validating forwarding delegation authentication for %s failed: %w", candidate, authErr)
		}
		switch delegationStatus {
		case DNSSECSecure:
			childDNSKEY, err := r.queryType(ctx, original, candidate, dns.TypeDNSKEY)
			if err != nil {
				return nil, true, fmt.Errorf("goreecloud dns: validating forwarding DNSKEY lookup for %s failed: %w", candidate, err)
			}
			childKeys, keyStatus, err := r.validator.AuthenticateDNSKEYResponse(candidate, childDNSKEY, childDS)
			if err != nil || keyStatus != DNSSECSecure {
				if err == nil {
					err = fmt.Errorf("DNSKEY RRset for %s did not establish secure trust: %s", candidate, keyStatus)
				}
				return nil, true, fmt.Errorf("goreecloud dns: validating forwarding child DNSSEC authentication failed: %w", err)
			}
			parentKeys = childKeys
		case DNSSECInsecure:
			return nil, false, nil
		case DNSSECIndeterminate:
			nonDelegationStatus, err := r.validator.AuthenticateNonDelegationDS(candidate, dsMsg, parentKeys)
			if err != nil {
				return nil, true, fmt.Errorf("goreecloud dns: validating forwarding non-delegation proof for %s failed: %w", candidate, err)
			}
			if nonDelegationStatus != DNSSECSecure {
				return nil, true, fmt.Errorf("goreecloud dns: validating forwarding cannot classify DS state for %s: %s", candidate, nonDelegationStatus)
			}
		default:
			return nil, true, fmt.Errorf("goreecloud dns: validating forwarding delegation for %s is %s", candidate, delegationStatus)
		}
	}
	return parentKeys, true, nil
}

func (r *ValidatingForwardingResolver) queryType(ctx context.Context, original *Request, name string, qtype uint16) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.CheckingDisabled = true
	lookup := *original
	lookup.Message = msg
	lookup.CompactAnswersOK = true
	res, err := r.forwarder.Resolve(ctx, &lookup)
	if err != nil {
		return nil, err
	}
	if res == nil || res.Message == nil {
		return nil, fmt.Errorf("goreecloud dns: validating forwarding %s lookup for %s returned no DNS response", dns.TypeToString[qtype], dns.Fqdn(name))
	}
	res.Message.AuthenticatedData = false
	return res.Message, nil
}

func forwardingValidationCandidates(qname string) ([]string, error) {
	qname = dns.Fqdn(qname)
	if _, ok := dns.IsDomainName(qname); !ok {
		return nil, fmt.Errorf("goreecloud dns: validating forwarding has invalid qname %q", qname)
	}
	labels := dns.SplitDomainName(qname)
	if len(labels) > maxForwardValidationLabels {
		return nil, errors.New("goreecloud dns: validating forwarding trust-walk label limit exceeded")
	}
	candidates := make([]string, 0, len(labels))
	for i := len(labels) - 1; i >= 0; i-- {
		candidates = append(candidates, dns.Fqdn(strings.Join(labels[i:], ".")))
	}
	return candidates, nil
}

func forwardingSignerZone(msg *dns.Msg) (string, bool, error) {
	if msg == nil {
		return "", false, nil
	}
	var signer string
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns} {
		for _, rr := range section {
			sig, ok := rr.(*dns.RRSIG)
			if !ok || strings.TrimSpace(sig.SignerName) == "" {
				continue
			}
			candidate := dns.CanonicalName(sig.SignerName)
			if signer == "" {
				signer = candidate
				continue
			}
			if signer != candidate {
				return "", false, fmt.Errorf("goreecloud dns: forwarded response spans multiple DNSSEC signer zones: %s and %s", signer, candidate)
			}
		}
	}
	if signer == "" {
		return "", false, nil
	}
	return dns.Fqdn(signer), true, nil
}

func forwardingAliasLinkMessage(msg *dns.Msg, current string, qtype uint16) (*dns.Msg, string, bool, error) {
	if msg == nil {
		return nil, "", false, errors.New("nil forwarding alias response")
	}
	if err := validateAliasAnswerShape(msg); err != nil {
		return nil, "", false, err
	}
	target, found, err := nextAliasTarget(msg, current, qtype)
	if err != nil || !found {
		return msg, "", false, err
	}
	current = dns.Fqdn(current)
	out := msg.Copy()
	out.Answer = nil
	dname, err := closestAnswerDNAME(msg, current)
	if err != nil {
		return nil, "", false, err
	}
	for _, rr := range msg.Answer {
		if rr == nil {
			continue
		}
		if dname != nil {
			if sameDNSName(rr.Header().Name, dname.Hdr.Name) {
				if rr.Header().Rrtype == dns.TypeDNAME {
					out.Answer = append(out.Answer, rr)
					continue
				}
				if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeDNAME {
					out.Answer = append(out.Answer, rr)
					continue
				}
			}
			if sameDNSName(rr.Header().Name, current) {
				if rr.Header().Rrtype == dns.TypeCNAME {
					out.Answer = append(out.Answer, rr)
					continue
				}
				if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeCNAME {
					out.Answer = append(out.Answer, rr)
					continue
				}
			}
			continue
		}
		if !sameDNSName(rr.Header().Name, current) {
			continue
		}
		if rr.Header().Rrtype == dns.TypeCNAME {
			out.Answer = append(out.Answer, rr)
			continue
		}
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeCNAME {
			out.Answer = append(out.Answer, rr)
		}
	}
	if len(out.Answer) == 0 {
		return nil, "", false, fmt.Errorf("alias target %s has no local alias RRset at %s", target, current)
	}
	return out, dns.Fqdn(target), true, nil
}

var _ Resolver = (*ValidatingForwardingResolver)(nil)
