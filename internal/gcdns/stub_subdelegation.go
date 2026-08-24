package gcdns

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

const maxStubDelegationDepth = 16

// DelegatingStubResolver starts from explicitly configured authoritative
// servers for one private/stub namespace and follows referrals only when every
// delegation remains strictly below that namespace. It does not fall back to
// Internet recursion for nameserver addresses outside the configured stub zone.
type DelegatingStubResolver struct {
	zone            string
	exchanger       DNSExchanger
	rootServers     []string
	schedulerConfig SchedulerConfig
}

func NewDelegatingStubResolver(exchanger DNSExchanger, zone string, servers []string, cfg SchedulerConfig) (*DelegatingStubResolver, error) {
	if exchanger == nil {
		return nil, errors.New("goreecloud dns: delegating stub resolver requires a DNS exchanger")
	}
	zone = dns.Fqdn(zone)
	if _, ok := dns.IsDomainName(zone); !ok {
		return nil, fmt.Errorf("goreecloud dns: delegating stub resolver has invalid zone %q", zone)
	}
	if _, err := routingTargets(servers, func(server string) Resolver {
		return &stubWalkTargetResolver{server: server, exchanger: exchanger}
	}); err != nil {
		return nil, err
	}
	if cfg.AttemptTimeout <= 0 {
		return nil, errors.New("goreecloud dns: delegating stub resolver attempt timeout must be positive")
	}
	if cfg.MaxConcurrent <= 0 {
		return nil, errors.New("goreecloud dns: delegating stub resolver max concurrency must be positive")
	}
	return &DelegatingStubResolver{
		zone:            zone,
		exchanger:       exchanger,
		rootServers:     append([]string(nil), servers...),
		schedulerConfig: cfg,
	}, nil
}

func (r *DelegatingStubResolver) Resolve(ctx context.Context, req *Request) (*Result, error) {
	return r.resolveWithState(ctx, req, newResolutionState())
}

func (r *DelegatingStubResolver) resolveWithState(ctx context.Context, req *Request, state *resolutionState) (*Result, error) {
	if req == nil || req.Message == nil || len(req.Message.Question) != 1 {
		return nil, errors.New("goreecloud dns: delegating stub resolver requires exactly one question")
	}
	qname := dns.Fqdn(req.Message.Question[0].Name)
	if !dns.IsSubDomain(r.zone, qname) {
		return nil, fmt.Errorf("goreecloud dns: delegating stub zone %s does not contain question %s", r.zone, qname)
	}
	if state == nil {
		state = newResolutionState()
	}

	servers := append([]string(nil), r.rootServers...)
	currentZone := r.zone
	seenDelegations := map[string]struct{}{}
	for depth := 0; depth < maxStubDelegationDepth; depth++ {
		res, err := r.resolveAgainst(ctx, req, servers)
		if err != nil {
			return nil, err
		}
		if terminalDNSResponse(res.Message) {
			res.CacheTTL = responseCacheTTL(res.Message)
			return res, nil
		}

		plan, err := buildReferralPlan(res.Message, qname)
		if err != nil {
			return nil, err
		}
		if !dns.IsSubDomain(r.zone, plan.zone) {
			return nil, fmt.Errorf("goreecloud dns: stub referral %s escapes configured zone %s", plan.zone, r.zone)
		}
		if !dns.IsSubDomain(currentZone, plan.zone) || equalName(currentZone, plan.zone) {
			return nil, fmt.Errorf("goreecloud dns: stub referral %s is not closer than current authority %s", plan.zone, currentZone)
		}

		nextServers, err := completeReferralServers(ctx, req, plan, state, r.resolveAddressWithinStub)
		if err != nil {
			return nil, err
		}
		key := delegationKey(plan.zone, nextServers)
		if _, exists := seenDelegations[key]; exists {
			return nil, fmt.Errorf("goreecloud dns: stub delegation loop detected at %s", plan.zone)
		}
		seenDelegations[key] = struct{}{}
		servers = nextServers
		currentZone = plan.zone
	}
	return nil, errors.New("goreecloud dns: stub delegation depth exceeded")
}

func (r *DelegatingStubResolver) resolveAddressWithinStub(ctx context.Context, req *Request, state *resolutionState) (*Result, error) {
	if req == nil || req.Message == nil || len(req.Message.Question) != 1 {
		return nil, errors.New("goreecloud dns: stub nameserver-address lookup requires exactly one question")
	}
	qname := dns.Fqdn(req.Message.Question[0].Name)
	if !dns.IsSubDomain(r.zone, qname) {
		return nil, fmt.Errorf("goreecloud dns: stub nameserver %s is outside configured zone %s", qname, r.zone)
	}
	return r.resolveWithState(ctx, req, state)
}

func (r *DelegatingStubResolver) resolveAgainst(ctx context.Context, req *Request, servers []string) (*Result, error) {
	targets, err := routingTargets(servers, func(server string) Resolver {
		return &stubWalkTargetResolver{server: server, exchanger: r.exchanger}
	})
	if err != nil {
		return nil, err
	}
	scheduler, err := NewTargetScheduler(targets, r.schedulerConfig)
	if err != nil {
		return nil, err
	}
	return scheduler.Resolve(ctx, req)
}

type stubWalkTargetResolver struct {
	server    string
	exchanger DNSExchanger
}

func (r *stubWalkTargetResolver) Resolve(ctx context.Context, req *Request) (*Result, error) {
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
	if msg == nil {
		return nil, errors.New("goreecloud dns: delegating stub target returned nil response")
	}
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("goreecloud dns: delegating stub target returned retryable rcode %s", dns.RcodeToString[msg.Rcode])
	}
	if terminalDNSResponse(msg) {
		if !msg.Authoritative {
			return nil, errors.New("goreecloud dns: delegating stub target returned a non-authoritative terminal response")
		}
	} else if _, err := buildReferralPlan(msg, query.Question[0].Name); err != nil {
		return nil, fmt.Errorf("goreecloud dns: delegating stub target returned neither terminal authority data nor a usable referral: %w", err)
	}
	msg.AuthenticatedData = false
	return &Result{Message: msg, Source: "stub:" + r.server, CacheTTL: time.Duration(0), DNSSECStatus: DNSSECIndeterminate}, nil
}

func (r *DelegatingStubResolver) routeTargetEndpoints() []string {
	return append([]string(nil), r.rootServers...)
}

var _ Resolver = (*DelegatingStubResolver)(nil)
