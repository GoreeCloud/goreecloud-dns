package gcdns

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

type dnssecChainValidator interface {
	ValidateRootDNSKEY(msg *dns.Msg, anchors []*dns.DS) (DNSSECStatus, []*dns.DNSKEY, error)
	ValidateSignedDelegation(parentKeys []*dns.DNSKEY, referral, childDNSKEY *dns.Msg, zone string) (DNSSECStatus, []*dns.DNSKEY, error)
	ValidateRRSet(rrset []dns.RR, signatures []*dns.RRSIG, keys []*dns.DNSKEY) (DNSSECStatus, error)
}

// DNSSECIterativeResolver performs the same local authoritative delegation walk
// as IterativeResolver while carrying an authenticated DNSSEC key chain from
// the root trust anchor to the terminal positive answer.
//
// Negative answers remain fail-closed until authenticated denial through
// NSEC/NSEC3 is implemented. This resolver is intentionally isolated from the
// inherited production request path until the remaining DNSSEC and recursion
// acceptance gates are complete.
type DNSSECIterativeResolver struct {
	conf      IterativeResolverConfig
	scheduler *ResolverScheduler
	roots     []ResolverTarget
	validator dnssecChainValidator
	anchors   []*dns.DS
}

// NewDNSSECIterativeResolver creates a bounded DNSSEC-validating iterative
// resolver. The trust-anchor set is defensively copied and must not be empty.
func NewDNSSECIterativeResolver(
	conf IterativeResolverConfig,
	scheduler *ResolverScheduler,
	roots []ResolverTarget,
	validator dnssecChainValidator,
	anchors []*dns.DS,
) (*DNSSECIterativeResolver, error) {
	if scheduler == nil {
		return nil, errors.New("goreecloud dns: dnssec iterative resolver requires a scheduler")
	}
	if validator == nil {
		return nil, errors.New("goreecloud dns: dnssec iterative resolver requires a validator")
	}
	if conf.MaxDepth <= 0 {
		return nil, errors.New("goreecloud dns: dnssec iterative resolver max depth must be positive")
	}
	validated, err := validateResolverTargets(roots)
	if err != nil {
		return nil, fmt.Errorf("goreecloud dns: invalid dnssec root bootstrap targets: %w", err)
	}
	if len(anchors) == 0 {
		return nil, errors.New("goreecloud dns: dnssec iterative resolver requires root trust anchors")
	}
	anchorCopy := make([]*dns.DS, 0, len(anchors))
	for _, anchor := range anchors {
		if anchor == nil {
			continue
		}
		copyAnchor := *anchor
		anchorCopy = append(anchorCopy, &copyAnchor)
	}
	if len(anchorCopy) == 0 {
		return nil, errors.New("goreecloud dns: dnssec iterative resolver has no usable root trust anchors")
	}
	return &DNSSECIterativeResolver{
		conf:      conf,
		scheduler: scheduler,
		roots:     validated,
		validator: validator,
		anchors:   anchorCopy,
	}, nil
}

// Resolve authenticates the root DNSKEY RRset, walks referrals, authenticates
// each signed DS -> DNSKEY transition, and validates every terminal positive
// answer RRset before returning a secure result.
func (r *DNSSECIterativeResolver) Resolve(ctx context.Context, req *Request) (*Result, error) {
	if req == nil || req.Message == nil {
		return nil, errors.New("goreecloud dns: nil dnssec iterative resolver request")
	}
	if len(req.Message.Question) != 1 {
		return nil, errors.New("goreecloud dns: dnssec iterative resolver requires exactly one question")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	rootKeys, err := r.authenticateRoot(ctx, req)
	if err != nil {
		return nil, err
	}

	query := req.Message.Copy()
	query.RecursionDesired = false
	ensureDNSSECOK(query)
	stepReq := *req
	stepReq.Message = query

	targets := append([]ResolverTarget(nil), r.roots...)
	parentKeys := rootKeys
	seenDelegations := make(map[string]struct{}, r.conf.MaxDepth)

	for depth := 0; depth < r.conf.MaxDepth; depth++ {
		res, err := r.scheduler.ResolveTargets(ctx, &stepReq, targets)
		if err != nil {
			return nil, fmt.Errorf("goreecloud dns: dnssec iterative resolution depth %d failed: %w", depth, err)
		}
		if res == nil || res.Message == nil {
			return nil, errors.New("goreecloud dns: dnssec iterative resolver received nil response")
		}

		if isTerminalDNSResponse(res.Message) {
			status, err := r.validateTerminalPositive(res.Message, parentKeys)
			if err != nil {
				return nil, fmt.Errorf("goreecloud dns: terminal dnssec validation failed: %w", err)
			}
			out := cloneResult(res)
			out.CacheTTL = responseCacheTTL(out.Message)
			out.DNSSECStatus = status
			return out, nil
		}

		zone, nextTargets, err := referralTargets(res.Message, query.Question[0].Name)
		if err != nil {
			return nil, fmt.Errorf("goreecloud dns: dnssec iterative referral rejected at depth %d: %w", depth, err)
		}
		key := delegationKey(zone, nextTargets)
		if _, ok := seenDelegations[key]; ok {
			return nil, fmt.Errorf("goreecloud dns: dnssec iterative delegation loop detected for %s", zone)
		}
		seenDelegations[key] = struct{}{}

		childDNSKEY, err := r.fetchDNSKEY(ctx, req, zone, nextTargets)
		if err != nil {
			return nil, fmt.Errorf("goreecloud dns: child DNSKEY acquisition failed for %s: %w", zone, err)
		}
		status, childKeys, err := r.validator.ValidateSignedDelegation(parentKeys, res.Message, childDNSKEY, zone)
		if err != nil || status != DNSSECSecure {
			if err == nil {
				err = fmt.Errorf("unexpected validation state %s", status)
			}
			return nil, fmt.Errorf("goreecloud dns: signed delegation validation failed for %s: %w", zone, err)
		}
		parentKeys = childKeys
		targets = nextTargets
	}

	return nil, fmt.Errorf("goreecloud dns: dnssec iterative resolver exceeded maximum delegation depth %d", r.conf.MaxDepth)
}

func (r *DNSSECIterativeResolver) authenticateRoot(ctx context.Context, req *Request) ([]*dns.DNSKEY, error) {
	msg, err := r.fetchDNSKEY(ctx, req, ".", r.roots)
	if err != nil {
		return nil, fmt.Errorf("goreecloud dns: root DNSKEY acquisition failed: %w", err)
	}
	status, keys, err := r.validator.ValidateRootDNSKEY(msg, r.anchors)
	if err != nil || status != DNSSECSecure {
		if err == nil {
			err = fmt.Errorf("unexpected validation state %s", status)
		}
		return nil, fmt.Errorf("goreecloud dns: root DNSKEY authentication failed: %w", err)
	}
	return keys, nil
}

func (r *DNSSECIterativeResolver) fetchDNSKEY(ctx context.Context, req *Request, zone string, targets []ResolverTarget) (*dns.Msg, error) {
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(zone), dns.TypeDNSKEY)
	query.RecursionDesired = false
	ensureDNSSECOK(query)
	keyReq := *req
	keyReq.Message = query

	res, err := r.scheduler.ResolveTargets(ctx, &keyReq, targets)
	if err != nil {
		return nil, err
	}
	if res == nil || res.Message == nil {
		return nil, errors.New("dnskey query returned nil response")
	}
	if res.Message.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dnskey query returned %s", dns.RcodeToString[res.Message.Rcode])
	}
	return res.Message, nil
}

func (r *DNSSECIterativeResolver) validateTerminalPositive(msg *dns.Msg, keys []*dns.DNSKEY) (DNSSECStatus, error) {
	if msg == nil {
		return DNSSECBogus, errors.New("nil terminal response")
	}
	if msg.Rcode == dns.RcodeNameError || (msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0) {
		return DNSSECIndeterminate, errors.New("authenticated denial with NSEC/NSEC3 is required for negative answers")
	}
	if msg.Rcode != dns.RcodeSuccess {
		return DNSSECBogus, fmt.Errorf("terminal response returned %s", dns.RcodeToString[msg.Rcode])
	}
	if len(keys) == 0 {
		return DNSSECIndeterminate, errors.New("terminal response has no authenticated zone keys")
	}

	type rrsetKey struct {
		name   string
		rrtype uint16
	}
	rrsets := make(map[rrsetKey][]dns.RR)
	signatures := make(map[rrsetKey][]*dns.RRSIG)
	for _, rr := range msg.Answer {
		switch record := rr.(type) {
		case *dns.RRSIG:
			key := rrsetKey{name: strings.ToLower(dns.Fqdn(record.Hdr.Name)), rrtype: record.TypeCovered}
			signatures[key] = append(signatures[key], record)
		default:
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			key := rrsetKey{name: strings.ToLower(dns.Fqdn(rr.Header().Name)), rrtype: rr.Header().Rrtype}
			rrsets[key] = append(rrsets[key], rr)
		}
	}
	if len(rrsets) == 0 {
		return DNSSECIndeterminate, errors.New("terminal response has no positive RRset to validate")
	}

	ordered := make([]rrsetKey, 0, len(rrsets))
	for key := range rrsets {
		ordered = append(ordered, key)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].name == ordered[j].name {
			return ordered[i].rrtype < ordered[j].rrtype
		}
		return ordered[i].name < ordered[j].name
	})
	for _, key := range ordered {
		sigs := signatures[key]
		if len(sigs) == 0 {
			return DNSSECBogus, fmt.Errorf("terminal RRset %s/%s has no RRSIG", key.name, dns.TypeToString[key.rrtype])
		}
		status, err := r.validator.ValidateRRSet(rrsets[key], sigs, keys)
		if err != nil || status != DNSSECSecure {
			if err == nil {
				err = fmt.Errorf("unexpected validation state %s", status)
			}
			return DNSSECBogus, fmt.Errorf("terminal RRset %s/%s failed validation: %w", key.name, dns.TypeToString[key.rrtype], err)
		}
	}
	return DNSSECSecure, nil
}
