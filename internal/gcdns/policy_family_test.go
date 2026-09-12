package gcdns

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestBuildFamilyPolicyRulesBlocksCategoryAndService(t *testing.T) {
	rules, err := BuildFamilyPolicyRules(PolicyFamilyConfig{
		IDPrefix:          "family",
		Priority:          50,
		BlockedCategories: []string{"adult"},
		BlockedServices:   []string{"games"},
	})
	require.NoError(t, err)

	engine, err := NewPolicyProfileEngine(PolicyProfileEngineConfig{
		DefaultProfileID: "family",
		Catalog: PolicyCatalog{
			Categories: map[string][]string{"adult": {"adult.example"}},
			Services:   map[string][]string{"games": {"games.example"}},
		},
		Profiles: []PolicyProfile{{ID: "family", Rules: rules}},
	})
	require.NoError(t, err)

	for _, name := range []string{"site.adult.example", "play.games.example"} {
		res, handled, evalErr := engine.Evaluate(context.Background(), policyTestRequest(name, dns.TypeA, "child", "192.0.2.10"))
		require.NoError(t, evalErr)
		require.True(t, handled)
		require.Equal(t, dns.RcodeRefused, res.Message.Rcode)
	}
}

func TestBuildFamilyPolicyRulesSafeSearchRewriteAndTargetExemption(t *testing.T) {
	rules, err := BuildFamilyPolicyRules(PolicyFamilyConfig{
		IDPrefix: "family",
		Priority: 75,
		SafeSearch: []PolicySafeSearchEnforcement{{
			ID:      "search",
			Domains: []string{"search.example"},
			Target:  "safe.search.example",
			TTL:     300,
		}},
	})
	require.NoError(t, err)

	engine, err := NewPolicyProfileEngine(PolicyProfileEngineConfig{
		DefaultProfileID: "family",
		Profiles:         []PolicyProfile{{ID: "family", Rules: rules}},
	})
	require.NoError(t, err)

	res, handled, err := engine.Evaluate(context.Background(), policyTestRequest("www.search.example", dns.TypeA, "child", ""))
	require.NoError(t, err)
	require.True(t, handled)
	require.Equal(t, DNSSECIndeterminate, res.DNSSECStatus)
	require.Len(t, res.Message.Answer, 1)
	cname, ok := res.Message.Answer[0].(*dns.CNAME)
	require.True(t, ok)
	require.Equal(t, "safe.search.example.", cname.Target)
	require.Equal(t, uint32(300), cname.Hdr.Ttl)

	res, handled, err = engine.Evaluate(context.Background(), policyTestRequest("safe.search.example", dns.TypeA, "child", ""))
	require.NoError(t, err)
	require.False(t, handled)
	require.Nil(t, res)
}

func TestBuildFamilyPolicyRulesScheduleCarriesToGeneratedRules(t *testing.T) {
	mondayMorning := time.Date(2026, 8, 31, 8, 30, 0, 0, time.UTC)
	rules, err := BuildFamilyPolicyRules(PolicyFamilyConfig{
		IDPrefix:          "school-night",
		BlockedCategories: []string{"social"},
		Schedule: &PolicySchedule{
			Days:        []time.Weekday{time.Monday},
			StartMinute: 8 * 60,
			EndMinute:   9 * 60,
			Timezone:    "UTC",
		},
	})
	require.NoError(t, err)

	engine, err := NewPolicyProfileEngine(PolicyProfileEngineConfig{
		DefaultProfileID: "family",
		Now:              func() time.Time { return mondayMorning },
		Catalog:          PolicyCatalog{Categories: map[string][]string{"social": {"social.example"}}},
		Profiles:         []PolicyProfile{{ID: "family", Rules: rules}},
	})
	require.NoError(t, err)

	_, handled, err := engine.Evaluate(context.Background(), policyTestRequest("chat.social.example", dns.TypeA, "child", ""))
	require.NoError(t, err)
	require.True(t, handled)
}

func TestBuildFamilyPolicyRulesDeterministicOrdering(t *testing.T) {
	rules, err := BuildFamilyPolicyRules(PolicyFamilyConfig{
		IDPrefix:          "family",
		BlockedCategories: []string{"zeta", "alpha"},
		BlockedServices:   []string{"video", "games"},
		SafeSearch: []PolicySafeSearchEnforcement{
			{ID: "zeta", Domains: []string{"z.example"}, Target: "safe-z.example"},
			{ID: "alpha", Domains: []string{"b.example", "a.example"}, Target: "safe-a.example"},
		},
	})
	require.NoError(t, err)

	ids := make([]string, 0, len(rules))
	for _, rule := range rules {
		ids = append(ids, rule.ID)
	}
	require.Equal(t, []string{
		"family:category:alpha",
		"family:category:zeta",
		"family:service:games",
		"family:service:video",
		"family:safesearch:alpha:target",
		"family:safesearch:alpha:domain:001",
		"family:safesearch:alpha:domain:002",
		"family:safesearch:zeta:target",
		"family:safesearch:zeta:domain:001",
	}, ids)
}

func TestBuildFamilyPolicyRulesRejectsOverlappingSafeSearchTargets(t *testing.T) {
	_, err := BuildFamilyPolicyRules(PolicyFamilyConfig{
		IDPrefix: "family",
		SafeSearch: []PolicySafeSearchEnforcement{
			{ID: "one", Domains: []string{"search.example"}, Target: "safe-one.example"},
			{ID: "two", Domains: []string{"child.search.example"}, Target: "safe-two.example"},
		},
	})
	require.ErrorContains(t, err, "overlapping protected domains")
}

func TestBuildFamilyPolicyRulesRejectsTargetEqualProtectedDomain(t *testing.T) {
	_, err := BuildFamilyPolicyRules(PolicyFamilyConfig{
		IDPrefix: "family",
		SafeSearch: []PolicySafeSearchEnforcement{{
			ID:      "search",
			Domains: []string{"safe.example"},
			Target:  "safe.example",
		}},
	})
	require.ErrorContains(t, err, "target must differ")
}

func TestBuildFamilyPolicyRulesRejectsTargetInsideDifferentMapping(t *testing.T) {
	_, err := BuildFamilyPolicyRules(PolicyFamilyConfig{
		IDPrefix: "family",
		SafeSearch: []PolicySafeSearchEnforcement{
			{ID: "one", Domains: []string{"one.example"}, Target: "safe.two.example"},
			{ID: "two", Domains: []string{"two.example"}, Target: "safe-two.example"},
		},
	})
	require.ErrorContains(t, err, "falls under")
}
