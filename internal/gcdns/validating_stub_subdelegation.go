package gcdns

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// ValidatingDelegatingStubResolver follows private stub delegations while
// carrying DNSSEC trust from an explicitly configured DNSKEY trust anchor at
// the stub-zone apex. It never accepts upstream AD as validation evidence.
type ValidatingDelegatingStubResolver struct {
	zone            string
	exchanger       DNSExchanger
	rootServers     []string
	schedulerConfig SchedulerConfig
	anchors         []*dns.DNSKEY
	validator       *DNSSECValidator
	runtimeBoundary *routingRuntimeBoundary
}

func NewValidatingDelegatingStubResolver(exchanger DNSExchanger, zone string, servers []string, cfg SchedulerConfig, anchor PrivateDNSKEYTrustAnchor, validator *DNSSECValidator) (*ValidatingDelegatingStubResolver, error) {
	stub, err := NewDelegatingStubResolver(exchanger, zone, servers, cfg)
	if err != nil {
		return nil, err
	}
	validatedAnchor, err := NewPrivateTrustAnchorResolver(stub, anchor, validator)
	if err != nil {
		return nil, err
	}
	if !sameDNSName(stub.zone, validatedAnchor.zone) {
		return nil, fmt.Errorf("goreecloud dns: validating stub zone %s does not match private trust-anchor zone %s", stub.zone, validatedAnchor.zone)
	}
	return &ValidatingDelegatingStubResolver{
		zone:            stub.zone,
		exchanger:       stub.exchanger,
		rootServers:     append([]string(nil), stub.rootServers...),
		schedulerConfig: stub.schedulerConfig,
		anchors:         append([]*dns.DNSKEY(nil), validatedAnchor.anchors...),
		validator:       validator,
	}, nil
}

func (r *ValidatingDelegatingStubResolver) Resolve(ctx context.Context, req *Request) (*Result, error) {
	return r.resolveWithState(ctx, req, newResolutionState())
}

func (r *ValidatingDelegatingStubResolver) resolveWithState(ctx context.Context, req *Request, state *resolutionState) (*Result, error) {
	if req == nil || req.Message == nil || len(req.Message.Question) != 1 {
		return nil, errors.New("goreecloud dns: validating delegating stub resolver requires exactly one question")
	}
	qname := dns.Fqdn(req.Message.Question[0].Name)
	if !dns.IsSubDomain(r.zone, qname) {
		return nil, fmt.Errorf("goreecloud dns: validating stub zone %s does not contain question %s", r.zone, qname)
	}
	if state == nil {
		state = newResolutionState()
	}

	parentKeys, err := r.resolveAnchoredApexKeys(ctx, req)
	if err != nil {
		return nil, err
	}

	upstreamReq := copyRequestForLocalValidation(req)
	upstreamReq.CompactAnswersOK = true
	servers := append([]string(nil), r.rootServers...)
	currentZone := r.zone
	chainSecure := true
	seenDelegations := map[string]struct{}{}

	for depth := 0; depth < maxStubDelegationDepth; depth++ {
		res, err := r.resolveAgainst(ctx, upstreamReq, servers)
		if err != nil {
			return nil, err
		}
		if terminalDNSResponse(res.Message) {
			res.CacheTTL = responseCacheTTL(res.Message)
			res.Message.AuthenticatedData = false
			res.Message.CheckingDisabled = req.Message.CheckingDisabled
			if !chainSecure {
				res.DNSSECStatus = DNSSECInsecure
				return res, nil
			}
			status, err := r.validator.AuthenticateTerminalAnswer(res.Message, parentKeys)
			if err != nil {
				return nil, fmt.Errorf("goreecloud dns: validating stub terminal DNSSEC authentication failed: %w", err)
			}
			if status != DNSSECSecure {
				return nil, fmt.Errorf("goreecloud dns: validating stub terminal response for %s is %s", qname, status)
			}
			res.DNSSECStatus = DNSSECSecure
			present, responseCO := compactDenialMessageMetadata(res.Message)
			res.CompactDenial = present
			res.CompactDenialCO = present && responseCO
			return res, nil
		}

		plan, err := buildReferralPlan(res.Message, qname)
		if err != nil {
			return nil, err
		}
		if !dns.IsSubDomain(r.zone, plan.zone) {
			return nil, fmt.Errorf("goreecloud dns: validating stub referral %s escapes configured zone %s", plan.zone, r.zone)
		}
		if !dns.IsSubDomain(currentZone, plan.zone) || equalName(currentZone, plan.zone) {
			return nil, fmt.Errorf("goreecloud dns: validating stub referral %s is not closer than current authority %s", plan.zone, currentZone)
		}

		var childDS []*dns.DS
		if chainSecure {
			childDS, status, authErr := r.validator.AuthenticateDelegationDS(plan.zone, res.Message, parentKeys)
			if authErr != nil {
				return nil, fmt.Errorf("goreecloud dns: validating stub delegation authentication failed: %w", authErr)
			}
			switch status {
			case DNSSECInsecure:
				chainSecure = false
				parentKeys = nil
			case DNSSECSecure:
				// The child DNSKEY RRset is authenticated after its authoritative
				// server addresses are established from the referral.
			case DNSSECIndeterminate:
				return nil, fmt.Errorf("goreecloud dns: validating stub delegation for %s lacks authenticated DS or denial proof", plan.zone)
			default:
				return nil, fmt.Errorf("goreecloud dns: validating stub delegation for %s is %s", plan.zone, status)
			}
		}

		nextServers, err := completeReferralServers(ctx, upstreamReq, plan, state, r.resolveAddressWithinStub)
		if err != nil {
			return nil, err
		}
		if r.runtimeBoundary != nil {
			for _, server := range nextServers {
				if err := r.runtimeBoundary.validateTarget(fmt.Sprintf("validating stub referral %s", plan.zone), server); err != nil {
					return nil, err
				}
			}
		}
		key := delegationKey(plan.zone, nextServers)
		if _, exists := seenDelegations[key]; exists {
			return nil, fmt.Errorf("goreecloud dns: validating stub delegation loop detected at %s", plan.zone)
		}
		seenDelegations[key] = struct{}{}

		if chainSecure {
			childDNSKEY, err := r.resolveDNSKEY(ctx, plan.zone, nextServers, req)
			if err != nil {
				return nil, fmt.Errorf("goreecloud dns: validating stub DNSKEY acquisition for %s failed: %w", plan.zone, err)
			}
			childKeys, status, err := r.validator.AuthenticateDNSKEYResponse(plan.zone, childDNSKEY, childDS)
			if err != nil || status != DNSSECSecure {
				if err == nil {
					err = fmt.Errorf("DNSKEY RRset for %s did not establish secure trust", plan.zone)
				}
				return nil, fmt.Errorf("goreecloud dns: validating stub child DNSSEC authentication failed: %w", err)
			}
			parentKeys = childKeys
		}

		servers = nextServers
		currentZone = plan.zone
	}
	return nil, errors.New("goreecloud dns: validating stub delegation depth exceeded")
}

func (r *ValidatingDelegatingStubResolver) resolveAnchoredApexKeys(ctx context.Context, req *Request) ([]*dns.DNSKEY, error) {
	msg, err := r.resolveDNSKEY(ctx, r.zone, r.rootServers, req)
	if err != nil {
		return nil, fmt.Errorf("goreecloud dns: validating stub apex DNSKEY acquisition failed: %w", err)
	}
	keys, status, err := r.validator.AuthenticateDNSKEYTrustAnchor(r.zone, msg, r.anchors)
	if err != nil {
		return nil, fmt.Errorf("goreecloud dns: validating stub apex trust-anchor authentication failed: %w", err)
	}
	if status != DNSSECSecure {
		return nil, fmt.Errorf("goreecloud dns: validating stub apex trust-anchor state is %s", status)
	}
	return keys, nil
}

func (r *ValidatingDelegatingStubResolver) resolveDNSKEY(ctx context.Context, zone string, servers []string, original *Request) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(zone), dns.TypeDNSKEY)
	msg.CheckingDisabled = true
	lookup := *original
	lookup.Message = msg
	lookup.CompactAnswersOK = true
	res, err := r.resolveAgainst(ctx, &lookup, servers)
	if err != nil {
		return nil, err
	}
	if res == nil || res.Message == nil {
		return nil, fmt.Errorf("goreecloud dns: validating stub DNSKEY lookup for %s returned no response", dns.Fqdn(zone))
	}
	res.Message.AuthenticatedData = false
	return res.Message, nil
}

func (r *ValidatingDelegatingStubResolver) resolveAddressWithinStub(ctx context.Context, req *Request, state *resolutionState) (*Result, error) {
	if req == nil || req.Message == nil || len(req.Message.Question) != 1 {
		return nil, errors.New("goreecloud dns: validating stub nameserver-address lookup requires exactly one question")
	}
	qname := dns.Fqdn(req.Message.Question[0].Name)
	if !dns.IsSubDomain(r.zone, qname) {
		return nil, fmt.Errorf("goreecloud dns: validating stub nameserver %s is outside configured zone %s", qname, r.zone)
	}
	return r.resolveWithState(ctx, req, state)
}

func (r *ValidatingDelegatingStubResolver) resolveAgainst(ctx context.Context, req *Request, servers []string) (*Result, error) {
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

func (r *ValidatingDelegatingStubResolver) routeTargetEndpoints() []string {
	return append([]string(nil), r.rootServers...)
}

var _ Resolver = (*ValidatingDelegatingStubResolver)(nil)
var _ = time.Duration(0)
