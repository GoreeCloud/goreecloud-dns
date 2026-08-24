package gcdns

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSExchanger is the transport boundary used by the iterative resolver.
type DNSExchanger interface {
	Exchange(ctx context.Context, server string, msg *dns.Msg) (*dns.Msg, error)
}

// IterativeResolverConfig controls bounded native delegation walking.
type IterativeResolverConfig struct {
	RootServers    []string
	MaxDepth       int
	AttemptTimeout time.Duration
	MaxConcurrent  int
}

// IterativeResolver performs non-recursive delegation walking using Beacon's
// native scheduler and transport boundaries.
type IterativeResolver struct {
	exchanger      DNSExchanger
	rootServers    []string
	maxDepth       int
	attemptTimeout time.Duration
	maxConcurrent  int
}

func NewIterativeResolver(exchanger DNSExchanger, cfg IterativeResolverConfig) (*IterativeResolver, error) {
	if exchanger == nil {
		return nil, errors.New("goreecloud dns: iterative resolver requires a DNS exchanger")
	}
	if len(cfg.RootServers) == 0 {
		cfg.RootServers = DefaultRootServers()
	}
	if cfg.MaxDepth <= 0 {
		return nil, errors.New("goreecloud dns: iterative resolver max depth must be positive")
	}
	if cfg.AttemptTimeout <= 0 {
		return nil, errors.New("goreecloud dns: iterative resolver attempt timeout must be positive")
	}
	if cfg.MaxConcurrent <= 0 {
		return nil, errors.New("goreecloud dns: iterative resolver max concurrency must be positive")
	}
	return &IterativeResolver{
		exchanger:      exchanger,
		rootServers:    append([]string(nil), cfg.RootServers...),
		maxDepth:       cfg.MaxDepth,
		attemptTimeout: cfg.AttemptTimeout,
		maxConcurrent:  cfg.MaxConcurrent,
	}, nil
}

func (r *IterativeResolver) Resolve(ctx context.Context, req *Request) (*Result, error) {
	return r.resolveWithState(ctx, req, newResolutionState())
}

func (r *IterativeResolver) resolveWithState(ctx context.Context, req *Request, state *resolutionState) (*Result, error) {
	if req == nil || req.Message == nil {
		return nil, errors.New("goreecloud dns: iterative resolver request is nil")
	}
	if len(req.Message.Question) != 1 {
		return nil, errors.New("goreecloud dns: iterative resolver requires exactly one question")
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

	for aliasDepth := 0; aliasDepth < maxAliasTransitions; aliasDepth++ {
		res, err := r.resolveSingle(ctx, current, state)
		if err != nil {
			return nil, err
		}
		q := current.Message.Question[0]
		target, chase, err := unresolvedAliasTarget(res.Message, q.Name, q.Qtype)
		if err != nil {
			return nil, err
		}
		if !chase {
			if len(priorAnswers) == 0 {
				return res, nil
			}
			return mergeAliasResult(original, priorAnswers, priorTTL, res)
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

func (r *IterativeResolver) resolveSingle(ctx context.Context, req *Request, state *resolutionState) (*Result, error) {
	q := req.Message.Question[0]
	servers := append([]string(nil), r.rootServers...)
	seenDelegations := map[string]struct{}{}
	cursor := "."
	minimise := qnameMinimisationEligible(req)

	for delegations := 0; delegations < r.maxDepth; {
		if minimise {
			child, more, err := nextMinimisedQNAME(q.Name, cursor)
			if err != nil {
				return nil, err
			}
			if !more || !consumeQNAMEMinimisationBudget(state) {
				minimise = false
			} else {
				probeReq, err := qnameMinimisationProbe(req, child)
				if err != nil {
					return nil, err
				}
				probeRes, err := r.resolveAgainst(ctx, probeReq, servers)
				if err != nil {
					// Relaxed compatibility fallback: if a server or middlebox rejects a
					// minimised query, retry the original question without minimisation.
					minimise = false
				} else if !terminalDNSResponse(probeRes.Message) {
					plan, err := buildReferralPlan(probeRes.Message, q.Name)
					if err != nil {
						return nil, err
					}
					nextServers, err := completeReferralServers(ctx, req, plan, state, r.resolveWithState)
					if err != nil {
						return nil, err
					}
					key := delegationKey(plan.zone, nextServers)
					if _, exists := seenDelegations[key]; exists {
						return nil, fmt.Errorf("goreecloud dns: delegation loop detected at %s", plan.zone)
					}
					seenDelegations[key] = struct{}{}
					servers = nextServers
					cursor = plan.zone
					delegations++
					continue
				} else if sameDNSName(child, q.Name) && q.Qtype == qnameMinimisationQType {
					// The final minimisation probe is byte-for-byte the original DNS
					// question when the client also asked for A. Reuse it instead of
					// issuing a redundant full-QNAME A query.
					probeRes.CacheTTL = responseCacheTTL(probeRes.Message)
					return probeRes, nil
				} else if probeRes.Message != nil && probeRes.Message.Rcode == dns.RcodeSuccess && !qnameMinimisationResponseHasDNAME(probeRes.Message) {
					// RFC 9156 relaxed mode: NOERROR, including NODATA and CNAME,
					// means no zone cut was learned here. Reveal the next label.
					cursor = child
					continue
				} else if probeRes.Message != nil && probeRes.Message.Rcode == dns.RcodeNameError {
					// Beacon does not yet use RFC 8020 NXDOMAIN cuts. Continue building
					// the original QNAME instead of returning the ancestor NXDOMAIN.
					cursor = child
					continue
				} else {
					// DNAME and non-NOERROR/NXDOMAIN responses use the ordinary full
					// question path so existing alias and compatibility handling owns them.
					minimise = false
				}
			}
		}

		res, err := r.resolveAgainst(ctx, req, servers)
		if err != nil {
			return nil, err
		}
		if terminalDNSResponse(res.Message) {
			res.CacheTTL = responseCacheTTL(res.Message)
			return res, nil
		}

		plan, err := buildReferralPlan(res.Message, q.Name)
		if err != nil {
			return nil, err
		}
		nextServers, err := completeReferralServers(ctx, req, plan, state, r.resolveWithState)
		if err != nil {
			return nil, err
		}
		key := delegationKey(plan.zone, nextServers)
		if _, exists := seenDelegations[key]; exists {
			return nil, fmt.Errorf("goreecloud dns: delegation loop detected at %s", plan.zone)
		}
		seenDelegations[key] = struct{}{}
		servers = nextServers
		cursor = plan.zone
		delegations++
	}
	return nil, errors.New("goreecloud dns: iterative resolver delegation depth exceeded")
}

func (r *IterativeResolver) resolveAgainst(ctx context.Context, req *Request, servers []string) (*Result, error) {
	targets := make([]ResolverTarget, 0, len(servers))
	for _, server := range servers {
		targets = append(targets, ResolverTarget{Name: server, Resolver: &exchangeResolver{server: server, exchanger: r.exchanger}})
	}
	scheduler, err := NewTargetScheduler(targets, SchedulerConfig{AttemptTimeout: r.attemptTimeout, MaxConcurrent: r.maxConcurrent})
	if err != nil {
		return nil, err
	}
	return scheduler.Resolve(ctx, req)
}

type exchangeResolver struct {
	server    string
	exchanger DNSExchanger
}

func (r *exchangeResolver) Resolve(ctx context.Context, req *Request) (*Result, error) {
	if result, handled := compactDenialQueryResponse(req); handled {
		return result, nil
	}
	query := req.Message.Copy()
	query.RecursionDesired = false
	requestDNSSECMaterial(query)
	if req.CompactAnswersOK {
		query.IsEdns0().SetCo()
	}
	msg, err := r.exchanger.Exchange(ctx, r.server, query)
	if err != nil {
		return nil, err
	}
	return &Result{Message: msg, Source: r.server, DNSSECStatus: DNSSECIndeterminate}, nil
}

func requestDNSSECMaterial(msg *dns.Msg) {
	if msg == nil {
		return
	}
	if opt := msg.IsEdns0(); opt != nil {
		if opt.UDPSize() < 1232 {
			opt.SetUDPSize(1232)
		}
		opt.SetDo()
		return
	}
	msg.SetEdns0(1232, true)
}

func terminalDNSResponse(msg *dns.Msg) bool {
	if msg == nil {
		return false
	}
	if msg.Rcode != dns.RcodeSuccess {
		return true
	}
	if len(msg.Answer) > 0 {
		return true
	}
	if msg.Authoritative {
		return true
	}
	for _, rr := range msg.Ns {
		if _, ok := rr.(*dns.SOA); ok {
			return true
		}
	}
	return false
}

// referralTargets preserves the conservative direct-glue helper used by the
// focused referral tests. The resolver itself uses buildReferralPlan plus
// completeReferralServers so out-of-bailiwick NS names can be resolved safely.
func referralTargets(msg *dns.Msg, qname string) (string, []string, error) {
	plan, err := buildReferralPlan(msg, qname)
	if err != nil {
		return "", nil, err
	}
	if len(plan.servers) == 0 {
		return "", nil, fmt.Errorf("goreecloud dns: referral for %s has no usable in-bailiwick glue", plan.zone)
	}
	return plan.zone, append([]string(nil), plan.servers...), nil
}

func delegationKey(zone string, servers []string) string {
	copyServers := append([]string(nil), servers...)
	sort.Strings(copyServers)
	return strings.ToLower(dns.Fqdn(zone)) + "|" + strings.Join(copyServers, ",")
}

func responseCacheTTL(msg *dns.Msg) time.Duration {
	if msg == nil {
		return 0
	}
	var ttl uint32
	set := false
	consider := func(v uint32) {
		if !set || v < ttl {
			ttl = v
			set = true
		}
	}
	for _, rr := range msg.Answer {
		consider(rr.Header().Ttl)
	}
	if len(msg.Answer) == 0 {
		for _, rr := range msg.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				negative := soa.Hdr.Ttl
				if soa.Minttl < negative {
					negative = soa.Minttl
				}
				consider(negative)
			}
		}
	}
	if !set {
		return 0
	}
	return time.Duration(ttl) * time.Second
}

var _ Resolver = (*IterativeResolver)(nil)
