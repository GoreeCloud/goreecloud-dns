package gcdns

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// PolicySafeSearchEnforcement describes one DNS-level SafeSearch enforcement
// mapping. Domains are DNS suffixes rewritten to Target. The target receives an
// exact allow exemption at the same priority so a target beneath a protected
// suffix cannot rewrite to itself.
type PolicySafeSearchEnforcement struct {
	ID      string
	Domains []string
	Target  string
	TTL     uint32
}

// PolicyFamilyConfig compiles parental/family controls into ordinary Beacon
// policy rules. The generated rules use the same assignment, precedence,
// schedule, privacy-safe decision tracing, and synthetic-response boundaries as
// all other PolicyProfileEngine rules.
type PolicyFamilyConfig struct {
	IDPrefix          string
	Priority          int
	Schedule          *PolicySchedule
	BlockRcode        int
	BlockedCategories []string
	BlockedServices   []string
	SafeSearch        []PolicySafeSearchEnforcement
}

type compiledSafeSearchEnforcement struct {
	id      string
	domains []string
	target  string
	ttl     uint32
}

// BuildFamilyPolicyRules returns deterministic ordinary policy rules for
// category/service blocking and DNS-level SafeSearch enforcement. The caller
// inserts the returned rules into any reusable PolicyProfile.
func BuildFamilyPolicyRules(cfg PolicyFamilyConfig) ([]PolicyRule, error) {
	prefix := strings.TrimSpace(cfg.IDPrefix)
	if prefix == "" {
		return nil, errors.New("goreecloud dns: family policy ID prefix is required")
	}
	if cfg.BlockRcode != 0 && cfg.BlockRcode != dns.RcodeNameError && cfg.BlockRcode != dns.RcodeRefused {
		return nil, errors.New("goreecloud dns: family policy block rcode must be NXDOMAIN or REFUSED")
	}

	categories, err := normalizedPolicyIdentifiers(cfg.BlockedCategories, "family category")
	if err != nil {
		return nil, err
	}
	services, err := normalizedPolicyIdentifiers(cfg.BlockedServices, "family service")
	if err != nil {
		return nil, err
	}
	safeSearch, err := compileSafeSearchEnforcement(cfg.SafeSearch)
	if err != nil {
		return nil, err
	}

	rules := make([]PolicyRule, 0, len(categories)+len(services)+len(safeSearch)*2)
	for _, category := range categories {
		rules = append(rules, PolicyRule{
			ID:         prefix + ":category:" + category,
			Priority:   cfg.Priority,
			Action:     PolicyActionBlock,
			Match:      PolicyMatch{Kind: PolicyMatchCategory, Value: category},
			Schedule:   clonePolicySchedule(cfg.Schedule),
			BlockRcode: cfg.BlockRcode,
		})
	}
	for _, service := range services {
		rules = append(rules, PolicyRule{
			ID:         prefix + ":service:" + service,
			Priority:   cfg.Priority,
			Action:     PolicyActionBlock,
			Match:      PolicyMatch{Kind: PolicyMatchService, Value: service},
			Schedule:   clonePolicySchedule(cfg.Schedule),
			BlockRcode: cfg.BlockRcode,
		})
	}
	for _, enforcement := range safeSearch {
		// This same-priority exact allow outranks generated suffix rewrites and
		// prevents a protected target such as safe.search.example from being
		// rewritten back to itself.
		rules = append(rules, PolicyRule{
			ID:       prefix + ":safesearch:" + enforcement.id + ":target",
			Priority: cfg.Priority,
			Action:   PolicyActionAllow,
			Match:    PolicyMatch{Kind: PolicyMatchExact, Value: enforcement.target},
			Schedule: clonePolicySchedule(cfg.Schedule),
		})
		for i, domain := range enforcement.domains {
			rules = append(rules, PolicyRule{
				ID:       fmt.Sprintf("%s:safesearch:%s:domain:%03d", prefix, enforcement.id, i+1),
				Priority: cfg.Priority,
				Action:   PolicyActionRewrite,
				Match:    PolicyMatch{Kind: PolicyMatchSuffix, Value: domain},
				Schedule: clonePolicySchedule(cfg.Schedule),
				Rewrite:  PolicyRewrite{CNAME: enforcement.target, TTL: enforcement.ttl},
			})
		}
	}

	return rules, nil
}

func normalizedPolicyIdentifiers(values []string, kind string) ([]string, error) {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value == "" {
			return nil, fmt.Errorf("goreecloud dns: %s identifier is required", kind)
		}
		if _, exists := seen[value]; exists {
			return nil, fmt.Errorf("goreecloud dns: duplicate normalized %s %q", kind, value)
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func compileSafeSearchEnforcement(input []PolicySafeSearchEnforcement) ([]compiledSafeSearchEnforcement, error) {
	compiled := make([]compiledSafeSearchEnforcement, 0, len(input))
	seenIDs := make(map[string]struct{}, len(input))

	for _, raw := range input {
		id := strings.ToLower(strings.TrimSpace(raw.ID))
		if id == "" {
			return nil, errors.New("goreecloud dns: SafeSearch enforcement ID is required")
		}
		if _, exists := seenIDs[id]; exists {
			return nil, fmt.Errorf("goreecloud dns: duplicate normalized SafeSearch enforcement %q", id)
		}
		seenIDs[id] = struct{}{}

		target, err := normalizePolicyDomain(raw.Target)
		if err != nil {
			return nil, fmt.Errorf("goreecloud dns: SafeSearch %q target: %w", id, err)
		}
		if len(raw.Domains) == 0 {
			return nil, fmt.Errorf("goreecloud dns: SafeSearch %q requires at least one domain", id)
		}

		domains := make([]string, 0, len(raw.Domains))
		seenDomains := make(map[string]struct{}, len(raw.Domains))
		for _, rawDomain := range raw.Domains {
			domain, normalizeErr := normalizePolicyDomain(rawDomain)
			if normalizeErr != nil {
				return nil, fmt.Errorf("goreecloud dns: SafeSearch %q domain: %w", id, normalizeErr)
			}
			if domain == target {
				return nil, fmt.Errorf("goreecloud dns: SafeSearch %q target must differ from protected domain %q", id, domain)
			}
			if _, exists := seenDomains[domain]; exists {
				continue
			}
			seenDomains[domain] = struct{}{}
			domains = append(domains, domain)
		}
		sort.Strings(domains)
		compiled = append(compiled, compiledSafeSearchEnforcement{id: id, domains: domains, target: target, ttl: raw.TTL})
	}

	sort.Slice(compiled, func(i, j int) bool { return compiled[i].id < compiled[j].id })
	if err := validateSafeSearchAmbiguity(compiled); err != nil {
		return nil, err
	}
	return compiled, nil
}

func validateSafeSearchAmbiguity(enforcements []compiledSafeSearchEnforcement) error {
	for i := range enforcements {
		for j := i + 1; j < len(enforcements); j++ {
			left := enforcements[i]
			right := enforcements[j]
			if left.target == right.target {
				continue
			}
			for _, leftDomain := range left.domains {
				for _, rightDomain := range right.domains {
					if dns.IsSubDomain(leftDomain, rightDomain) || dns.IsSubDomain(rightDomain, leftDomain) {
						return fmt.Errorf("goreecloud dns: SafeSearch mappings %q and %q have overlapping protected domains with different targets", left.id, right.id)
					}
				}
				if dns.IsSubDomain(leftDomain, right.target) {
					return fmt.Errorf("goreecloud dns: SafeSearch target for %q falls under %q protected domain with a different target", right.id, left.id)
				}
			}
			for _, rightDomain := range right.domains {
				if dns.IsSubDomain(rightDomain, left.target) {
					return fmt.Errorf("goreecloud dns: SafeSearch target for %q falls under %q protected domain with a different target", left.id, right.id)
				}
			}
		}
	}
	return nil
}

func clonePolicySchedule(schedule *PolicySchedule) *PolicySchedule {
	if schedule == nil {
		return nil
	}
	clone := *schedule
	clone.Days = append([]time.Weekday(nil), schedule.Days...)
	return &clone
}
