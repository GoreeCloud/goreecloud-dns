package gcdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// RouteMode identifies how an explicitly matched namespace is resolved.
type RouteMode string

const (
	RouteRecursive RouteMode = "recursive"
	RouteForward   RouteMode = "forward"
	RouteStub      RouteMode = "stub"
)

// ResolverRoute is one longest-suffix routing rule. ClientIDs and
// ClientPrefixes are optional split-horizon selectors. An unscoped route is a
// namespace-wide default. Exact client identity outranks a matching network
// prefix; a longer network prefix outranks a shorter one.
type ResolverRoute struct {
	Name           string
	Suffix         string
	Mode           RouteMode
	Resolver       Resolver
	ClientIDs      []string
	ClientPrefixes []netip.Prefix
}

type resolverRouteScore struct {
	suffixLabels int
	scopeRank    int
	prefixBits   int
}

type routingContextKey struct{}

type routingContextState struct {
	active map[string]struct{}
}

// RoutingResolver chooses the most specific matching namespace and client
// scope. It falls back to Default when no route matches or when an explicit
// recursive route overrides a broader forwarding/stub rule.
type RoutingResolver struct {
	defaultResolver Resolver
	routes          []ResolverRoute
}

func NewRoutingResolver(defaultResolver Resolver, routes []ResolverRoute) (*RoutingResolver, error) {
	if defaultResolver == nil {
		return nil, errors.New("goreecloud dns: routing resolver requires a default recursive resolver")
	}
	copyRoutes := make([]ResolverRoute, len(routes))
	seenNames := map[string]struct{}{}
	for i, route := range routes {
		normalized, err := normalizeResolverRoute(route)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seenNames[normalized.Name]; duplicate {
			return nil, fmt.Errorf("goreecloud dns: duplicate resolver route name %q", normalized.Name)
		}
		seenNames[normalized.Name] = struct{}{}
		copyRoutes[i] = normalized
	}
	for i := range copyRoutes {
		for j := i + 1; j < len(copyRoutes); j++ {
			if staticRouteConflict(copyRoutes[i], copyRoutes[j]) {
				return nil, fmt.Errorf("goreecloud dns: ambiguous resolver routes %q and %q have the same namespace and client scope", copyRoutes[i].Name, copyRoutes[j].Name)
			}
		}
	}
	return &RoutingResolver{defaultResolver: defaultResolver, routes: copyRoutes}, nil
}

func normalizeResolverRoute(route ResolverRoute) (ResolverRoute, error) {
	route.Name = strings.TrimSpace(route.Name)
	if route.Name == "" {
		return ResolverRoute{}, errors.New("goreecloud dns: resolver route requires a name")
	}
	if strings.TrimSpace(route.Suffix) == "" {
		return ResolverRoute{}, fmt.Errorf("goreecloud dns: resolver route %q requires a namespace suffix", route.Name)
	}
	route.Suffix = dns.Fqdn(route.Suffix)
	if _, ok := dns.IsDomainName(route.Suffix); !ok {
		return ResolverRoute{}, fmt.Errorf("goreecloud dns: resolver route %q has invalid namespace %q", route.Name, route.Suffix)
	}
	switch route.Mode {
	case RouteRecursive:
		if route.Resolver != nil {
			return ResolverRoute{}, fmt.Errorf("goreecloud dns: recursive route %q must use the default resolver", route.Name)
		}
	case RouteForward, RouteStub:
		if route.Resolver == nil {
			return ResolverRoute{}, fmt.Errorf("goreecloud dns: %s route %q requires a resolver", route.Mode, route.Name)
		}
	default:
		return ResolverRoute{}, fmt.Errorf("goreecloud dns: resolver route %q has unsupported mode %q", route.Name, route.Mode)
	}

	seenIDs := map[string]struct{}{}
	for i, id := range route.ClientIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			return ResolverRoute{}, fmt.Errorf("goreecloud dns: resolver route %q contains an empty client id", route.Name)
		}
		if _, duplicate := seenIDs[id]; duplicate {
			return ResolverRoute{}, fmt.Errorf("goreecloud dns: resolver route %q repeats client id %q", route.Name, id)
		}
		seenIDs[id] = struct{}{}
		route.ClientIDs[i] = id
	}
	seenPrefixes := map[netip.Prefix]struct{}{}
	for _, prefix := range route.ClientPrefixes {
		if !prefix.IsValid() {
			return ResolverRoute{}, fmt.Errorf("goreecloud dns: resolver route %q contains an invalid client prefix", route.Name)
		}
		prefix = prefix.Masked()
		if _, duplicate := seenPrefixes[prefix]; duplicate {
			return ResolverRoute{}, fmt.Errorf("goreecloud dns: resolver route %q repeats client prefix %s", route.Name, prefix)
		}
		seenPrefixes[prefix] = struct{}{}
	}
	return route, nil
}

func staticRouteConflict(a, b ResolverRoute) bool {
	if !sameDNSName(a.Suffix, b.Suffix) {
		return false
	}
	aGlobal := len(a.ClientIDs) == 0 && len(a.ClientPrefixes) == 0
	bGlobal := len(b.ClientIDs) == 0 && len(b.ClientPrefixes) == 0
	if aGlobal && bGlobal {
		return true
	}
	for _, aID := range a.ClientIDs {
		for _, bID := range b.ClientIDs {
			if aID == bID {
				return true
			}
		}
	}
	for _, aPrefix := range a.ClientPrefixes {
		aPrefix = aPrefix.Masked()
		for _, bPrefix := range b.ClientPrefixes {
			if aPrefix == bPrefix.Masked() {
				return true
			}
		}
	}
	return false
}

func (r *RoutingResolver) Resolve(ctx context.Context, req *Request) (*Result, error) {
	if req == nil || req.Message == nil || len(req.Message.Question) != 1 {
		return nil, errors.New("goreecloud dns: routing resolver requires exactly one question")
	}

	original := req
	current := req
	seenAliases := map[string]struct{}{dns.CanonicalName(req.Message.Question[0].Name): {}}
	var priorAnswers []dns.RR
	var priorTTL time.Duration
	overallStatus := DNSSECSecure
	haveStatus := false

	for depth := 0; depth < maxAliasTransitions; depth++ {
		res, err := r.resolveOne(ctx, current)
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
			return nil, fmt.Errorf("goreecloud dns: routed alias processing failed: %w", err)
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
			return nil, fmt.Errorf("goreecloud dns: routed alias loop detected at %s", dns.Fqdn(target))
		}
		seenAliases[canonical] = struct{}{}
		current, err = aliasFollowupRequest(original, target)
		if err != nil {
			return nil, err
		}
	}
	return nil, errors.New("goreecloud dns: routed alias chain exceeds maximum transition depth")
}

func (r *RoutingResolver) resolveOne(ctx context.Context, req *Request) (*Result, error) {
	route, matched, err := r.selectRoute(req)
	if err != nil {
		return nil, err
	}
	if !matched || route.Mode == RouteRecursive {
		return r.defaultResolver.Resolve(ctx, req)
	}

	state, _ := ctx.Value(routingContextKey{}).(*routingContextState)
	if state == nil {
		state = &routingContextState{active: map[string]struct{}{}}
	}
	if _, active := state.active[route.Name]; active {
		return nil, fmt.Errorf("goreecloud dns: resolver route loop detected at %q", route.Name)
	}
	copyState := &routingContextState{active: make(map[string]struct{}, len(state.active)+1)}
	for name := range state.active {
		copyState.active[name] = struct{}{}
	}
	copyState.active[route.Name] = struct{}{}
	routeCtx := context.WithValue(ctx, routingContextKey{}, copyState)
	res, err := route.Resolver.Resolve(routeCtx, req)
	if err != nil {
		return nil, fmt.Errorf("goreecloud dns: resolver route %q: %w", route.Name, err)
	}
	if res == nil || res.Message == nil {
		return nil, fmt.Errorf("goreecloud dns: resolver route %q returned no DNS response", route.Name)
	}
	return res, nil
}

func (r *RoutingResolver) selectRoute(req *Request) (ResolverRoute, bool, error) {
	qname := dns.Fqdn(req.Message.Question[0].Name)
	var best ResolverRoute
	var bestScore resolverRouteScore
	haveBest := false
	for _, route := range r.routes {
		if !dns.IsSubDomain(route.Suffix, qname) {
			continue
		}
		score, matches := routeScore(route, req)
		if !matches {
			continue
		}
		if !haveBest || routeScoreLess(bestScore, score) {
			best, bestScore, haveBest = route, score, true
			continue
		}
		if score == bestScore {
			return ResolverRoute{}, false, fmt.Errorf("goreecloud dns: ambiguous resolver routes %q and %q match %s with equal specificity", best.Name, route.Name, qname)
		}
	}
	return best, haveBest, nil
}

func routeScore(route ResolverRoute, req *Request) (resolverRouteScore, bool) {
	score := resolverRouteScore{suffixLabels: len(dns.SplitDomainName(route.Suffix))}
	global := len(route.ClientIDs) == 0 && len(route.ClientPrefixes) == 0
	if global {
		return score, true
	}
	for _, id := range route.ClientIDs {
		if req.ClientID != "" && req.ClientID == id {
			score.scopeRank = 2
			return score, true
		}
	}
	if req.ClientIP.IsValid() {
		bestBits := -1
		for _, prefix := range route.ClientPrefixes {
			if prefix.Contains(req.ClientIP) && prefix.Bits() > bestBits {
				bestBits = prefix.Bits()
			}
		}
		if bestBits >= 0 {
			score.scopeRank = 1
			score.prefixBits = bestBits
			return score, true
		}
	}
	return resolverRouteScore{}, false
}

func routeScoreLess(a, b resolverRouteScore) bool {
	if a.suffixLabels != b.suffixLabels {
		return a.suffixLabels < b.suffixLabels
	}
	if a.scopeRank != b.scopeRank {
		return a.scopeRank < b.scopeRank
	}
	return a.prefixBits < b.prefixBits
}

// ForwardingResolver sends the full question to one of the configured recursive
// upstreams. Forwarded answers remain DNSSECIndeterminate until Beacon adds a
// local validating-forwarder path; an upstream AD bit is not accepted as local
// validation evidence.
type ForwardingResolver struct {
	scheduler *TargetScheduler
}

func NewForwardingResolver(exchanger DNSExchanger, servers []string, cfg SchedulerConfig) (*ForwardingResolver, error) {
	if exchanger == nil {
		return nil, errors.New("goreecloud dns: forwarding resolver requires a DNS exchanger")
	}
	targets, err := routingTargets(servers, func(server string) Resolver {
		return &forwardTargetResolver{server: server, exchanger: exchanger}
	})
	if err != nil {
		return nil, err
	}
	scheduler, err := NewTargetScheduler(targets, cfg)
	if err != nil {
		return nil, err
	}
	return &ForwardingResolver{scheduler: scheduler}, nil
}

func (r *ForwardingResolver) Resolve(ctx context.Context, req *Request) (*Result, error) {
	if req == nil || req.Message == nil || len(req.Message.Question) != 1 {
		return nil, errors.New("goreecloud dns: forwarding resolver requires exactly one question")
	}
	return r.scheduler.Resolve(ctx, req)
}

type forwardTargetResolver struct {
	server    string
	exchanger DNSExchanger
}

func (r *forwardTargetResolver) Resolve(ctx context.Context, req *Request) (*Result, error) {
	query := req.Message.Copy()
	query.RecursionDesired = true
	requestDNSSECMaterial(query)
	if req.CompactAnswersOK {
		query.IsEdns0().SetCo()
	}
	msg, err := r.exchanger.Exchange(ctx, r.server, query)
	if err != nil {
		return nil, err
	}
	if msg == nil {
		return nil, errors.New("goreecloud dns: forwarding target returned nil response")
	}
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("goreecloud dns: forwarding target returned retryable rcode %s", dns.RcodeToString[msg.Rcode])
	}
	msg.AuthenticatedData = false
	return &Result{Message: msg, Source: "forward:" + r.server, CacheTTL: responseCacheTTL(msg), DNSSECStatus: DNSSECIndeterminate}, nil
}

// StubResolver sends non-recursive full questions to explicitly configured
// authoritative servers for Zone. This first stub stage accepts only terminal
// authoritative NOERROR/NXDOMAIN responses; subdelegation walking is staged.
type StubResolver struct {
	zone      string
	scheduler *TargetScheduler
}

func NewStubResolver(exchanger DNSExchanger, zone string, servers []string, cfg SchedulerConfig) (*StubResolver, error) {
	if exchanger == nil {
		return nil, errors.New("goreecloud dns: stub resolver requires a DNS exchanger")
	}
	zone = dns.Fqdn(zone)
	if _, ok := dns.IsDomainName(zone); !ok {
		return nil, fmt.Errorf("goreecloud dns: stub resolver has invalid zone %q", zone)
	}
	targets, err := routingTargets(servers, func(server string) Resolver {
		return &stubTargetResolver{server: server, exchanger: exchanger}
	})
	if err != nil {
		return nil, err
	}
	scheduler, err := NewTargetScheduler(targets, cfg)
	if err != nil {
		return nil, err
	}
	return &StubResolver{zone: zone, scheduler: scheduler}, nil
}

func (r *StubResolver) Resolve(ctx context.Context, req *Request) (*Result, error) {
	if req == nil || req.Message == nil || len(req.Message.Question) != 1 {
		return nil, errors.New("goreecloud dns: stub resolver requires exactly one question")
	}
	if !dns.IsSubDomain(r.zone, dns.Fqdn(req.Message.Question[0].Name)) {
		return nil, fmt.Errorf("goreecloud dns: stub zone %s does not contain question %s", r.zone, dns.Fqdn(req.Message.Question[0].Name))
	}
	return r.scheduler.Resolve(ctx, req)
}

type stubTargetResolver struct {
	server    string
	exchanger DNSExchanger
}

func (r *stubTargetResolver) Resolve(ctx context.Context, req *Request) (*Result, error) {
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
		return nil, errors.New("goreecloud dns: stub target returned nil response")
	}
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("goreecloud dns: stub target returned retryable rcode %s", dns.RcodeToString[msg.Rcode])
	}
	if !msg.Authoritative || !terminalDNSResponse(msg) {
		return nil, errors.New("goreecloud dns: stub target did not return a terminal authoritative response")
	}
	msg.AuthenticatedData = false
	return &Result{Message: msg, Source: "stub:" + r.server, CacheTTL: responseCacheTTL(msg), DNSSECStatus: DNSSECIndeterminate}, nil
}

func routingTargets(servers []string, makeResolver func(string) Resolver) ([]ResolverTarget, error) {
	if len(servers) == 0 {
		return nil, errors.New("goreecloud dns: resolver route requires at least one target server")
	}
	seen := map[string]struct{}{}
	targets := make([]ResolverTarget, 0, len(servers))
	for _, server := range servers {
		server = strings.TrimSpace(server)
		if err := validateDNSTarget(server); err != nil {
			return nil, err
		}
		if _, duplicate := seen[server]; duplicate {
			return nil, fmt.Errorf("goreecloud dns: duplicate resolver target %q", server)
		}
		seen[server] = struct{}{}
		targets = append(targets, ResolverTarget{Name: server, Resolver: makeResolver(server)})
	}
	return targets, nil
}

func validateDNSTarget(server string) error {
	host, portText, err := net.SplitHostPort(server)
	if err != nil || strings.TrimSpace(host) == "" {
		return fmt.Errorf("goreecloud dns: invalid resolver target %q", server)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("goreecloud dns: invalid resolver target port in %q", server)
	}
	return nil
}

func sortedRouteNames(routes []ResolverRoute) []string {
	names := make([]string, 0, len(routes))
	for _, route := range routes {
		names = append(names, route.Name)
	}
	sort.Strings(names)
	return names
}

var (
	_ Resolver = (*RoutingResolver)(nil)
	_ Resolver = (*ForwardingResolver)(nil)
	_ Resolver = (*StubResolver)(nil)
)
