package gcdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

const maxNameServerAddressLookups = 32

type referralPlan struct {
	zone              string
	servers           []string
	outOfBailiwickNS  []string
	missingInDomainNS []string
}

type resolutionState struct {
	nsAddresses              map[string][]string
	nsActive                 map[string]struct{}
	nsLookups                int
	qnameMinimisationQueries int
}

type internalResolveFunc func(context.Context, *Request, *resolutionState) (*Result, error)

func newResolutionState() *resolutionState {
	return &resolutionState{
		nsAddresses: make(map[string][]string),
		nsActive:    make(map[string]struct{}),
	}
}

// buildReferralPlan accepts only glue that is required for a nameserver below
// the delegated child. Addresses for sibling or unrelated nameservers are
// intentionally ignored and resolved through normal recursion instead.
func buildReferralPlan(msg *dns.Msg, qname string) (*referralPlan, error) {
	if msg == nil {
		return nil, errors.New("goreecloud dns: nil referral response")
	}
	qname = dns.Fqdn(qname)
	var zone string
	nsHosts := map[string]string{}
	for _, rr := range msg.Ns {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		owner := dns.Fqdn(ns.Hdr.Name)
		if !dns.IsSubDomain(owner, qname) {
			continue
		}
		if zone == "" {
			zone = owner
		} else if !equalName(zone, owner) {
			return nil, errors.New("goreecloud dns: mixed referral zones are not accepted")
		}
		host := dns.Fqdn(ns.Ns)
		nsHosts[dns.CanonicalName(host)] = host
	}
	if zone == "" || len(nsHosts) == 0 {
		return nil, errors.New("goreecloud dns: response does not contain a usable referral")
	}

	glue := map[string]map[string]struct{}{}
	for _, rr := range msg.Extra {
		if rr == nil {
			continue
		}
		owner := dns.CanonicalName(rr.Header().Name)
		host, advertised := nsHosts[owner]
		if !advertised || !dns.IsSubDomain(zone, host) {
			continue
		}
		endpoint, ok := rrAddressEndpoint(rr)
		if !ok {
			continue
		}
		if glue[owner] == nil {
			glue[owner] = map[string]struct{}{}
		}
		glue[owner][endpoint] = struct{}{}
	}

	plan := &referralPlan{zone: dns.Fqdn(zone)}
	for canonical, host := range nsHosts {
		if dns.IsSubDomain(zone, host) {
			if len(glue[canonical]) == 0 {
				plan.missingInDomainNS = append(plan.missingInDomainNS, host)
				continue
			}
			for endpoint := range glue[canonical] {
				plan.servers = append(plan.servers, endpoint)
			}
			continue
		}
		plan.outOfBailiwickNS = append(plan.outOfBailiwickNS, host)
	}
	sort.Strings(plan.servers)
	sort.Strings(plan.outOfBailiwickNS)
	sort.Strings(plan.missingInDomainNS)
	return plan, nil
}

func completeReferralServers(ctx context.Context, req *Request, plan *referralPlan, state *resolutionState, resolve internalResolveFunc) ([]string, error) {
	if plan == nil {
		return nil, errors.New("goreecloud dns: nil referral plan")
	}
	if state == nil {
		state = newResolutionState()
	}
	if resolve == nil {
		return nil, errors.New("goreecloud dns: nameserver discovery requires an internal resolver")
	}

	serverSet := map[string]struct{}{}
	for _, server := range plan.servers {
		serverSet[server] = struct{}{}
	}
	var lastDiscoveryErr error
	for _, host := range plan.outOfBailiwickNS {
		addresses, err := discoverNameServerAddresses(ctx, req, host, state, resolve)
		if err != nil {
			// A broken external nameserver must not prevent another advertised
			// nameserver from making the delegation reachable.
			lastDiscoveryErr = err
			continue
		}
		for _, server := range addresses {
			serverSet[server] = struct{}{}
		}
	}
	if len(serverSet) == 0 {
		if len(plan.missingInDomainNS) != 0 {
			return nil, fmt.Errorf("goreecloud dns: referral for %s is missing mandatory in-domain glue for %s", plan.zone, strings.Join(plan.missingInDomainNS, ", "))
		}
		if lastDiscoveryErr != nil {
			return nil, fmt.Errorf("goreecloud dns: referral for %s has no resolvable nameserver addresses: %w", plan.zone, lastDiscoveryErr)
		}
		return nil, fmt.Errorf("goreecloud dns: referral for %s has no resolvable nameserver addresses", plan.zone)
	}
	servers := make([]string, 0, len(serverSet))
	for server := range serverSet {
		servers = append(servers, server)
	}
	sort.Strings(servers)
	return servers, nil
}

func discoverNameServerAddresses(ctx context.Context, req *Request, host string, state *resolutionState, resolve internalResolveFunc) ([]string, error) {
	host = dns.Fqdn(host)
	key := dns.CanonicalName(host)
	if cached, ok := state.nsAddresses[key]; ok {
		return append([]string(nil), cached...), nil
	}
	if _, active := state.nsActive[key]; active {
		return nil, fmt.Errorf("goreecloud dns: nameserver address discovery cycle at %s", host)
	}
	if state.nsLookups >= maxNameServerAddressLookups {
		return nil, errors.New("goreecloud dns: nameserver address discovery work limit exceeded")
	}
	state.nsLookups++
	state.nsActive[key] = struct{}{}
	defer delete(state.nsActive, key)

	serverSet := map[string]struct{}{}
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		lookup := new(dns.Msg)
		lookup.SetQuestion(host, qtype)
		lookupReq := &Request{Message: lookup, Transport: TransportDNS}
		if req != nil {
			lookupReq.Transport = req.Transport
			lookupReq.CompactAnswersOK = req.CompactAnswersOK
		}
		res, err := resolve(ctx, lookupReq, state)
		if err != nil {
			continue
		}
		for _, endpoint := range resolvedAddressEndpoints(res.Message, host, qtype) {
			serverSet[endpoint] = struct{}{}
		}
	}
	if len(serverSet) == 0 {
		return nil, fmt.Errorf("goreecloud dns: nameserver %s has no resolvable A or AAAA address", host)
	}
	servers := make([]string, 0, len(serverSet))
	for server := range serverSet {
		servers = append(servers, server)
	}
	sort.Strings(servers)
	state.nsAddresses[key] = append([]string(nil), servers...)
	return servers, nil
}

func resolvedAddressEndpoints(msg *dns.Msg, qname string, qtype uint16) []string {
	if msg == nil || (qtype != dns.TypeA && qtype != dns.TypeAAAA) {
		return nil
	}
	if err := validateAliasAnswerShape(msg); err != nil {
		return nil
	}
	current := dns.Fqdn(qname)
	seen := map[string]struct{}{dns.CanonicalName(current): {}}
	for depth := 0; depth < maxAliasTransitions; depth++ {
		if answerHasTypeAt(msg, current, qtype) {
			break
		}
		target, found, err := nextAliasTarget(msg, current, qtype)
		if err != nil || !found {
			return nil
		}
		current = dns.Fqdn(target)
		canonical := dns.CanonicalName(current)
		if _, duplicate := seen[canonical]; duplicate {
			return nil
		}
		seen[canonical] = struct{}{}
	}

	set := map[string]struct{}{}
	for _, rr := range msg.Answer {
		if rr == nil || !sameDNSName(rr.Header().Name, current) || rr.Header().Rrtype != qtype {
			continue
		}
		if endpoint, ok := rrAddressEndpoint(rr); ok {
			set[endpoint] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for endpoint := range set {
		out = append(out, endpoint)
	}
	sort.Strings(out)
	return out
}

func rrAddressEndpoint(rr dns.RR) (string, bool) {
	switch value := rr.(type) {
	case *dns.A:
		ip := value.A.To4()
		if ip == nil {
			return "", false
		}
		return net.JoinHostPort(net.IP(ip).String(), "53"), true
	case *dns.AAAA:
		ip := value.AAAA.To16()
		if ip == nil {
			return "", false
		}
		return net.JoinHostPort(net.IP(ip).String(), "53"), true
	default:
		return "", false
	}
}
