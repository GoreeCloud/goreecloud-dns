package gcdns

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func policyFilterListDigest(content []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(content))
}

func TestBuildPolicyFilterListRulesCompilesSupportedForms(t *testing.T) {
	content := []byte("# reviewed list\nexample.com\n||ads.example^\n0.0.0.0 tracker.example\n@@||allowed.example^\n")
	rules, err := BuildPolicyFilterListRules(PolicyFilterListConfig{
		ID:             "reviewed",
		Priority:       40,
		ExpectedSHA256: policyFilterListDigest(content),
		Content:        content,
	})
	require.NoError(t, err)
	require.Len(t, rules, 4)
	require.Equal(t, "reviewed:allow:000001", rules[0].ID)
	require.Equal(t, PolicyActionAllow, rules[0].Action)
	require.Equal(t, 41, rules[0].Priority)
	require.Equal(t, "allowed.example.", rules[0].Match.Value)
	require.Equal(t, "reviewed:block:000001", rules[1].ID)
	require.Equal(t, 40, rules[1].Priority)
	for _, rule := range rules {
		require.Equal(t, PolicyMatchSuffix, rule.Match.Kind)
	}
}

func TestBuildPolicyFilterListRulesSameListAllowExceptionWins(t *testing.T) {
	content := []byte("ads.example\n@@safe.ads.example\n")
	rules, err := BuildPolicyFilterListRules(PolicyFilterListConfig{
		ID:             "ads",
		Priority:       25,
		ExpectedSHA256: policyFilterListDigest(content),
		Content:        content,
	})
	require.NoError(t, err)

	engine, err := NewPolicyProfileEngine(PolicyProfileEngineConfig{
		DefaultProfileID: "default",
		Profiles:         []PolicyProfile{{ID: "default", Rules: rules}},
	})
	require.NoError(t, err)

	res, handled, err := engine.Evaluate(context.Background(), policyTestRequest("banner.ads.example", dns.TypeA, "client", ""))
	require.NoError(t, err)
	require.True(t, handled)
	require.Equal(t, dns.RcodeRefused, res.Message.Rcode)

	res, handled, err = engine.Evaluate(context.Background(), policyTestRequest("safe.ads.example", dns.TypeA, "client", ""))
	require.NoError(t, err)
	require.False(t, handled)
	require.Nil(t, res)
}

func TestBuildPolicyFilterListRulesAllowCanOverrideWithHigherPriority(t *testing.T) {
	blockContent := []byte("ads.example\n")
	allowContent := []byte("@@safe.ads.example\n")
	blockRules, err := BuildPolicyFilterListRules(PolicyFilterListConfig{
		ID:             "block",
		Priority:       20,
		ExpectedSHA256: policyFilterListDigest(blockContent),
		Content:        blockContent,
	})
	require.NoError(t, err)
	allowRules, err := BuildPolicyFilterListRules(PolicyFilterListConfig{
		ID:             "allow",
		Priority:       30,
		ExpectedSHA256: policyFilterListDigest(allowContent),
		Content:        allowContent,
	})
	require.NoError(t, err)

	engine, err := NewPolicyProfileEngine(PolicyProfileEngineConfig{
		DefaultProfileID: "default",
		Profiles:         []PolicyProfile{{ID: "default", Rules: append(blockRules, allowRules...)}},
	})
	require.NoError(t, err)

	res, handled, err := engine.Evaluate(context.Background(), policyTestRequest("safe.ads.example", dns.TypeA, "client", ""))
	require.NoError(t, err)
	require.False(t, handled)
	require.Nil(t, res)
}

func TestBuildPolicyFilterListRulesRejectsDigestMismatch(t *testing.T) {
	content := []byte("example.com\n")
	_, err := BuildPolicyFilterListRules(PolicyFilterListConfig{
		ID:             "reviewed",
		ExpectedSHA256: fmt.Sprintf("%064x", 1),
		Content:        content,
	})
	require.ErrorContains(t, err, "SHA-256 mismatch")
}

func TestBuildPolicyFilterListRulesRejectsMissingDigest(t *testing.T) {
	_, err := BuildPolicyFilterListRules(PolicyFilterListConfig{ID: "reviewed", Content: []byte("example.com\n")})
	require.ErrorContains(t, err, "64 hexadecimal")
}

func TestBuildPolicyFilterListRulesRejectsConflictingNormalizedEntries(t *testing.T) {
	content := []byte("example.com\n@@EXAMPLE.COM.\n")
	_, err := BuildPolicyFilterListRules(PolicyFilterListConfig{
		ID:             "reviewed",
		ExpectedSHA256: policyFilterListDigest(content),
		Content:        content,
	})
	require.ErrorContains(t, err, "conflicting allow/block entries")
}

func TestBuildPolicyFilterListRulesRejectsUnsupportedHostsAddress(t *testing.T) {
	content := []byte("192.0.2.10 example.com\n")
	_, err := BuildPolicyFilterListRules(PolicyFilterListConfig{
		ID:             "reviewed",
		ExpectedSHA256: policyFilterListDigest(content),
		Content:        content,
	})
	require.ErrorContains(t, err, "unsupported hosts-file address")
}

func TestBuildPolicyFilterListRulesRejectsUnsupportedSyntax(t *testing.T) {
	content := []byte("/example\\.com/\n")
	_, err := BuildPolicyFilterListRules(PolicyFilterListConfig{
		ID:             "reviewed",
		ExpectedSHA256: policyFilterListDigest(content),
		Content:        content,
	})
	require.Error(t, err)
}

func TestBuildPolicyFilterListRulesRejectsBrowserOnlyOptions(t *testing.T) {
	content := []byte("||example.com^$third-party\n")
	_, err := BuildPolicyFilterListRules(PolicyFilterListConfig{
		ID:             "reviewed",
		ExpectedSHA256: policyFilterListDigest(content),
		Content:        content,
	})
	require.ErrorContains(t, err, "unsupported filter-list domain syntax")
}

func TestBuildPolicyFilterListRulesDeduplicatesEquivalentEntries(t *testing.T) {
	content := []byte("example.com\nEXAMPLE.COM.\n||example.com^\n")
	rules, err := BuildPolicyFilterListRules(PolicyFilterListConfig{
		ID:             "reviewed",
		ExpectedSHA256: policyFilterListDigest(content),
		Content:        content,
	})
	require.NoError(t, err)
	require.Len(t, rules, 1)
}

func TestBuildPolicyFilterListRulesRejectsMaxPriorityWithAllow(t *testing.T) {
	content := []byte("@@example.com\n")
	_, err := BuildPolicyFilterListRules(PolicyFilterListConfig{
		ID:             "reviewed",
		Priority:       int(^uint(0) >> 1),
		ExpectedSHA256: policyFilterListDigest(content),
		Content:        content,
	})
	require.ErrorContains(t, err, "priority is too high")
}
