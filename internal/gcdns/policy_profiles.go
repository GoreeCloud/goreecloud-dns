package gcdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// PolicyAction is the terminal action selected by a Beacon policy rule.
type PolicyAction string

const (
	PolicyActionAllow   PolicyAction = "allow"
	PolicyActionBlock   PolicyAction = "block"
	PolicyActionRewrite PolicyAction = "rewrite"
)

// PolicyMatchKind identifies the first-party selector used by a policy rule.
type PolicyMatchKind string

const (
	PolicyMatchExact    PolicyMatchKind = "exact"
	PolicyMatchSuffix   PolicyMatchKind = "suffix"
	PolicyMatchCategory PolicyMatchKind = "category"
	PolicyMatchService  PolicyMatchKind = "service"
)

// PolicySchedule limits a rule to selected local days and times.  Days is
// optional; an empty list means every day.  StartMinute and EndMinute are
// minutes after local midnight.  Equal start/end values mean the entire day.
type PolicySchedule struct {
	Days        []time.Weekday
	StartMinute int
	EndMinute   int
	Timezone    string
}

// PolicyMatch describes a rule selector.  Exact and suffix values are DNS
// names.  Category and service values reference entries in PolicyCatalog.
type PolicyMatch struct {
	Kind  PolicyMatchKind
	Value string
}

// PolicyRewrite is a first-party DNS rewrite.  A rule may return either one or
// more literal IP addresses or a CNAME target, but not both.
type PolicyRewrite struct {
	Addresses []netip.Addr
	CNAME     string
	TTL       uint32
}

// PolicyRule is one deterministic rule inside a policy profile.
type PolicyRule struct {
	ID         string
	Priority   int
	Action     PolicyAction
	Match      PolicyMatch
	Schedule   *PolicySchedule
	BlockRcode int
	Rewrite    PolicyRewrite
}

// PolicyProfile is a reusable policy bundle that can be assigned to clients or
// networks.  Rule order in the input does not control precedence.
type PolicyProfile struct {
	ID    string
	Rules []PolicyRule
}

// PolicyAssignment binds exactly one client ID or network prefix to a profile.
type PolicyAssignment struct {
	ProfileID string
	ClientID  string
	Prefix    netip.Prefix
}

// PolicyCatalog contains local first-party category and service membership.
// Values are DNS suffixes and are normalized during engine construction.
type PolicyCatalog struct {
	Categories map[string][]string
	Services   map[string][]string
}

// PolicyDecision is intentionally privacy-minimized.  It omits the queried
// name, client address, client identifier, and matched catalog/domain value.
type PolicyDecision struct {
	ProfileID       string
	RuleID          string
	Action          PolicyAction
	AssignmentScope string
	MatchKind       PolicyMatchKind
}

// PolicyDecisionRecorder receives privacy-safe policy decision metadata.
type PolicyDecisionRecorder interface {
	RecordPolicyDecision(ctx context.Context, decision PolicyDecision)
}

// PolicyProfileEngineConfig configures the first-party Beacon policy engine.
type PolicyProfileEngineConfig struct {
	Profiles         []PolicyProfile
	Assignments      []PolicyAssignment
	DefaultProfileID string
	Catalog          PolicyCatalog
	DecisionRecorder PolicyDecisionRecorder
	Now              func() time.Time
}

type compiledPolicyRule struct {
	rule     PolicyRule
	value    string
	location *time.Location
	days     [7]bool
	allDays  bool
}

type compiledPolicyProfile struct {
	id    string
	rules []compiledPolicyRule
}

type compiledAssignment struct {
	profileID string
	clientID  string
	prefix    netip.Prefix
}

// PolicyProfileEngine applies reusable profiles, client/network assignment,
// schedules, category/service controls, custom domain rules, and DNS rewrites
// through the native Pipeline Policy boundary.
type PolicyProfileEngine struct {
	profiles         map[string]compiledPolicyProfile
	assignments      []compiledAssignment
	defaultProfileID string
	categories       map[string][]string
	services         map[string][]string
	recorder         PolicyDecisionRecorder
	now              func() time.Time
}

// NewPolicyProfileEngine validates and compiles a deterministic policy model.
func NewPolicyProfileEngine(cfg PolicyProfileEngineConfig) (*PolicyProfileEngine, error) {
	if strings.TrimSpace(cfg.DefaultProfileID) == "" {
		return nil, errors.New("goreecloud dns: default policy profile is required")
	}

	engine := &PolicyProfileEngine{
		profiles:         make(map[string]compiledPolicyProfile, len(cfg.Profiles)),
		defaultProfileID: cfg.DefaultProfileID,
		categories:       make(map[string][]string),
		services:         make(map[string][]string),
		recorder:         cfg.DecisionRecorder,
		now:              cfg.Now,
	}
	if engine.now == nil {
		engine.now = time.Now
	}

	var err error
	if engine.categories, err = compilePolicyCatalog(cfg.Catalog.Categories); err != nil {
		return nil, fmt.Errorf("goreecloud dns: policy category catalog: %w", err)
	}
	if engine.services, err = compilePolicyCatalog(cfg.Catalog.Services); err != nil {
		return nil, fmt.Errorf("goreecloud dns: policy service catalog: %w", err)
	}

	for _, profile := range cfg.Profiles {
		id := strings.TrimSpace(profile.ID)
		if id == "" {
			return nil, errors.New("goreecloud dns: policy profile ID is required")
		}
		if _, exists := engine.profiles[id]; exists {
			return nil, fmt.Errorf("goreecloud dns: duplicate policy profile %q", id)
		}

		compiled := compiledPolicyProfile{id: id, rules: make([]compiledPolicyRule, 0, len(profile.Rules))}
		seenRules := make(map[string]struct{}, len(profile.Rules))
		for _, rule := range profile.Rules {
			cr, compileErr := compilePolicyRule(rule, engine.categories, engine.services)
			if compileErr != nil {
				return nil, fmt.Errorf("goreecloud dns: profile %q: %w", id, compileErr)
			}
			if _, exists := seenRules[cr.rule.ID]; exists {
				return nil, fmt.Errorf("goreecloud dns: profile %q has duplicate rule %q", id, cr.rule.ID)
			}
			seenRules[cr.rule.ID] = struct{}{}
			compiled.rules = append(compiled.rules, cr)
		}
		sort.SliceStable(compiled.rules, func(i, j int) bool {
			left, right := compiled.rules[i], compiled.rules[j]
			if left.rule.Priority != right.rule.Priority {
				return left.rule.Priority > right.rule.Priority
			}
			if policyMatchSpecificity(left.rule.Match.Kind) != policyMatchSpecificity(right.rule.Match.Kind) {
				return policyMatchSpecificity(left.rule.Match.Kind) > policyMatchSpecificity(right.rule.Match.Kind)
			}
			return left.rule.ID < right.rule.ID
		})
		engine.profiles[id] = compiled
	}

	if _, ok := engine.profiles[cfg.DefaultProfileID]; !ok {
		return nil, fmt.Errorf("goreecloud dns: default policy profile %q does not exist", cfg.DefaultProfileID)
	}

	seenClient := make(map[string]string)
	seenPrefix := make(map[netip.Prefix]string)
	for _, assignment := range cfg.Assignments {
		if _, ok := engine.profiles[assignment.ProfileID]; !ok {
			return nil, fmt.Errorf("goreecloud dns: assignment references unknown profile %q", assignment.ProfileID)
		}
		clientID := strings.TrimSpace(assignment.ClientID)
		hasPrefix := assignment.Prefix.IsValid()
		if (clientID == "") == !hasPrefix {
			return nil, errors.New("goreecloud dns: policy assignment must select exactly one client ID or network prefix")
		}

		ca := compiledAssignment{profileID: assignment.ProfileID, clientID: clientID}
		if clientID != "" {
			if prior, exists := seenClient[clientID]; exists && prior != assignment.ProfileID {
				return nil, fmt.Errorf("goreecloud dns: conflicting client policy assignment for %q", clientID)
			}
			seenClient[clientID] = assignment.ProfileID
		} else {
			ca.prefix = assignment.Prefix.Masked()
			if prior, exists := seenPrefix[ca.prefix]; exists && prior != assignment.ProfileID {
				return nil, fmt.Errorf("goreecloud dns: conflicting network policy assignment for %s", ca.prefix)
			}
			seenPrefix[ca.prefix] = assignment.ProfileID
		}
		engine.assignments = append(engine.assignments, ca)
	}

	sort.SliceStable(engine.assignments, func(i, j int) bool {
		left, right := engine.assignments[i], engine.assignments[j]
		if (left.clientID != "") != (right.clientID != "") {
			return left.clientID != ""
		}
		if left.clientID != "" {
			return left.clientID < right.clientID
		}
		if left.prefix.Bits() != right.prefix.Bits() {
			return left.prefix.Bits() > right.prefix.Bits()
		}
		return left.prefix.String() < right.prefix.String()
	})

	return engine, nil
}

func compilePolicyCatalog(input map[string][]string) (map[string][]string, error) {
	out := make(map[string][]string, len(input))
	for key, values := range input {
		name := strings.ToLower(strings.TrimSpace(key))
		if name == "" {
			return nil, errors.New("catalog entry name is required")
		}
		if len(values) == 0 {
			return nil, fmt.Errorf("catalog entry %q has no DNS suffixes", key)
		}
		compiled := make([]string, 0, len(values))
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			normalized, err := normalizePolicyDomain(value)
			if err != nil {
				return nil, fmt.Errorf("catalog entry %q: %w", key, err)
			}
			if _, exists := seen[normalized]; exists {
				continue
			}
			seen[normalized] = struct{}{}
			compiled = append(compiled, normalized)
		}
		sort.Strings(compiled)
		out[name] = compiled
	}
	return out, nil
}

func compilePolicyRule(rule PolicyRule, categories, services map[string][]string) (compiledPolicyRule, error) {
	rule.ID = strings.TrimSpace(rule.ID)
	if rule.ID == "" {
		return compiledPolicyRule{}, errors.New("policy rule ID is required")
	}
	if rule.Action != PolicyActionAllow && rule.Action != PolicyActionBlock && rule.Action != PolicyActionRewrite {
		return compiledPolicyRule{}, fmt.Errorf("rule %q has unsupported action %q", rule.ID, rule.Action)
	}

	compiled := compiledPolicyRule{rule: rule, allDays: true}
	var err error
	switch rule.Match.Kind {
	case PolicyMatchExact, PolicyMatchSuffix:
		compiled.value, err = normalizePolicyDomain(rule.Match.Value)
	case PolicyMatchCategory:
		compiled.value = strings.ToLower(strings.TrimSpace(rule.Match.Value))
		if _, ok := categories[compiled.value]; !ok {
			return compiledPolicyRule{}, fmt.Errorf("rule %q references unknown category %q", rule.ID, rule.Match.Value)
		}
	case PolicyMatchService:
		compiled.value = strings.ToLower(strings.TrimSpace(rule.Match.Value))
		if _, ok := services[compiled.value]; !ok {
			return compiledPolicyRule{}, fmt.Errorf("rule %q references unknown service %q", rule.ID, rule.Match.Value)
		}
	default:
		return compiledPolicyRule{}, fmt.Errorf("rule %q has unsupported match kind %q", rule.ID, rule.Match.Kind)
	}
	if err != nil {
		return compiledPolicyRule{}, fmt.Errorf("rule %q: %w", rule.ID, err)
	}

	if rule.Action == PolicyActionBlock {
		if rule.BlockRcode == 0 {
			compiled.rule.BlockRcode = dns.RcodeRefused
		} else if rule.BlockRcode != dns.RcodeNameError && rule.BlockRcode != dns.RcodeRefused {
			return compiledPolicyRule{}, fmt.Errorf("rule %q block rcode must be NXDOMAIN or REFUSED", rule.ID)
		}
	}
	if rule.Action == PolicyActionRewrite {
		if err := validatePolicyRewrite(rule.Rewrite); err != nil {
			return compiledPolicyRule{}, fmt.Errorf("rule %q: %w", rule.ID, err)
		}
	}

	if rule.Schedule != nil {
		if rule.Schedule.StartMinute < 0 || rule.Schedule.StartMinute > 1439 || rule.Schedule.EndMinute < 0 || rule.Schedule.EndMinute > 1439 {
			return compiledPolicyRule{}, fmt.Errorf("rule %q schedule minute is outside 0..1439", rule.ID)
		}
		zone := strings.TrimSpace(rule.Schedule.Timezone)
		if zone == "" {
			zone = "UTC"
		}
		compiled.location, err = time.LoadLocation(zone)
		if err != nil {
			return compiledPolicyRule{}, fmt.Errorf("rule %q schedule timezone %q: %w", rule.ID, zone, err)
		}
		if len(rule.Schedule.Days) > 0 {
			compiled.allDays = false
			for _, day := range rule.Schedule.Days {
				if day < time.Sunday || day > time.Saturday {
					return compiledPolicyRule{}, fmt.Errorf("rule %q has invalid schedule weekday %d", rule.ID, day)
				}
				compiled.days[int(day)] = true
			}
		}
	}

	return compiled, nil
}

func validatePolicyRewrite(rewrite PolicyRewrite) error {
	hasAddresses := len(rewrite.Addresses) > 0
	hasCNAME := strings.TrimSpace(rewrite.CNAME) != ""
	if hasAddresses == hasCNAME {
		return errors.New("rewrite must define exactly one address set or CNAME target")
	}
	if hasAddresses {
		for _, addr := range rewrite.Addresses {
			if !addr.IsValid() || addr.IsUnspecified() {
				return fmt.Errorf("rewrite contains invalid or unspecified address %q", addr)
			}
		}
	}
	if hasCNAME {
		if _, err := normalizePolicyDomain(rewrite.CNAME); err != nil {
			return fmt.Errorf("invalid CNAME target: %w", err)
		}
	}
	return nil
}

func normalizePolicyDomain(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("DNS name is required")
	}
	fqdn := strings.ToLower(dns.Fqdn(value))
	if _, ok := dns.IsDomainName(fqdn); !ok {
		return "", fmt.Errorf("invalid DNS name %q", value)
	}
	return fqdn, nil
}

func policyMatchSpecificity(kind PolicyMatchKind) int {
	switch kind {
	case PolicyMatchExact:
		return 4
	case PolicyMatchSuffix:
		return 3
	case PolicyMatchService:
		return 2
	case PolicyMatchCategory:
		return 1
	default:
		return 0
	}
}

// Evaluate implements Policy for the native Beacon pipeline.
func (e *PolicyProfileEngine) Evaluate(ctx context.Context, req *Request) (*Result, bool, error) {
	if req == nil || req.Message == nil || len(req.Message.Question) != 1 {
		return nil, false, errors.New("goreecloud dns: policy engine requires exactly one DNS question")
	}

	profile, scope := e.profileForRequest(req)
	qname := strings.ToLower(dns.Fqdn(req.Message.Question[0].Name))
	now := e.now()

	for _, rule := range profile.rules {
		if !rule.activeAt(now) || !e.ruleMatches(rule, qname) {
			continue
		}
		decision := PolicyDecision{
			ProfileID:       profile.id,
			RuleID:          rule.rule.ID,
			Action:          rule.rule.Action,
			AssignmentScope: scope,
			MatchKind:       rule.rule.Match.Kind,
		}
		if e.recorder != nil {
			e.recorder.RecordPolicyDecision(ctx, decision)
		}

		switch rule.rule.Action {
		case PolicyActionAllow:
			return nil, false, nil
		case PolicyActionBlock:
			msg := new(dns.Msg)
			msg.SetRcode(req.Message, rule.rule.BlockRcode)
			return &Result{Message: msg, Source: "policy:" + rule.rule.ID}, true, nil
		case PolicyActionRewrite:
			msg, err := buildPolicyRewriteResponse(req.Message, rule.rule.Rewrite)
			if err != nil {
				return nil, false, fmt.Errorf("goreecloud dns: policy rewrite %q: %w", rule.rule.ID, err)
			}
			return &Result{Message: msg, Source: "policy:" + rule.rule.ID}, true, nil
		}
	}

	return nil, false, nil
}

func (e *PolicyProfileEngine) profileForRequest(req *Request) (compiledPolicyProfile, string) {
	for _, assignment := range e.assignments {
		if assignment.clientID != "" && assignment.clientID == req.ClientID {
			return e.profiles[assignment.profileID], "client"
		}
	}
	if req.ClientIP.IsValid() {
		for _, assignment := range e.assignments {
			if assignment.clientID == "" && assignment.prefix.Contains(req.ClientIP) {
				return e.profiles[assignment.profileID], "network"
			}
		}
	}
	return e.profiles[e.defaultProfileID], "default"
}

func (e *PolicyProfileEngine) ruleMatches(rule compiledPolicyRule, qname string) bool {
	switch rule.rule.Match.Kind {
	case PolicyMatchExact:
		return qname == rule.value
	case PolicyMatchSuffix:
		return dns.IsSubDomain(rule.value, qname)
	case PolicyMatchCategory:
		return policyCatalogMatches(e.categories[rule.value], qname)
	case PolicyMatchService:
		return policyCatalogMatches(e.services[rule.value], qname)
	default:
		return false
	}
}

func policyCatalogMatches(suffixes []string, qname string) bool {
	for _, suffix := range suffixes {
		if dns.IsSubDomain(suffix, qname) {
			return true
		}
	}
	return false
}

func (r compiledPolicyRule) activeAt(now time.Time) bool {
	if r.rule.Schedule == nil {
		return true
	}
	local := now.In(r.location)
	minute := local.Hour()*60 + local.Minute()
	start := r.rule.Schedule.StartMinute
	end := r.rule.Schedule.EndMinute

	dayAllowed := func(day time.Weekday) bool {
		return r.allDays || r.days[int(day)]
	}
	if start == end {
		return dayAllowed(local.Weekday())
	}
	if start < end {
		return dayAllowed(local.Weekday()) && minute >= start && minute < end
	}
	if minute >= start {
		return dayAllowed(local.Weekday())
	}
	if minute < end {
		previous := time.Weekday((int(local.Weekday()) + 6) % 7)
		return dayAllowed(previous)
	}
	return false
}

func buildPolicyRewriteResponse(request *dns.Msg, rewrite PolicyRewrite) (*dns.Msg, error) {
	if request == nil || len(request.Question) != 1 {
		return nil, errors.New("rewrite requires exactly one DNS question")
	}
	question := request.Question[0]
	ttl := rewrite.TTL
	if ttl == 0 {
		ttl = 60
	}

	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true

	if strings.TrimSpace(rewrite.CNAME) != "" {
		target, err := normalizePolicyDomain(rewrite.CNAME)
		if err != nil {
			return nil, err
		}
		response.Answer = append(response.Answer, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: question.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
			Target: target,
		})
		return response, nil
	}

	for _, addr := range rewrite.Addresses {
		switch {
		case addr.Is4() && (question.Qtype == dns.TypeA || question.Qtype == dns.TypeANY):
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   net.IP(addr.AsSlice()),
			})
		case addr.Is6() && (question.Qtype == dns.TypeAAAA || question.Qtype == dns.TypeANY):
			response.Answer = append(response.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				AAAA: net.IP(addr.AsSlice()),
			})
		}
	}
	return response, nil
}

var _ Policy = (*PolicyProfileEngine)(nil)
