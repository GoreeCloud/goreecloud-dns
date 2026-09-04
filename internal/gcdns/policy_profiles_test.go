package gcdns

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type policyDecisionRecorderStub struct {
	decisions []PolicyDecision
}

func (r *policyDecisionRecorderStub) RecordPolicyDecision(_ context.Context, decision PolicyDecision) {
	r.decisions = append(r.decisions, decision)
}

func policyTestRequest(name string, qtype uint16, clientID, clientIP string) *Request {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	req := &Request{Message: msg, ClientID: clientID, Transport: TransportDNS}
	if clientIP != "" {
		req.ClientIP = netip.MustParseAddr(clientIP)
	}
	return req
}

func TestPolicyProfileEngineClientAssignmentOverridesNetworkAndDefault(t *testing.T) {
	engine, err := NewPolicyProfileEngine(PolicyProfileEngineConfig{
		DefaultProfileID: "default",
		Profiles: []PolicyProfile{
			{ID: "default", Rules: []PolicyRule{{ID: "default-block", Priority: 10, Action: PolicyActionBlock, Match: PolicyMatch{Kind: PolicyMatchSuffix, Value: "example.org"}}}},
			{ID: "network", Rules: []PolicyRule{{ID: "network-block", Priority: 10, Action: PolicyActionBlock, Match: PolicyMatch{Kind: PolicyMatchSuffix, Value: "example.org"}}}},
			{ID: "client", Rules: []PolicyRule{{ID: "client-allow", Priority: 10, Action: PolicyActionAllow, Match: PolicyMatch{Kind: PolicyMatchSuffix, Value: "example.org"}}}},
		},
		Assignments: []PolicyAssignment{
			{ProfileID: "network", Prefix: netip.MustParsePrefix("10.0.0.0/8")},
			{ProfileID: "client", ClientID: "phone"},
		},
	})
	require.NoError(t, err)

	res, handled, err := engine.Evaluate(context.Background(), policyTestRequest("www.example.org", dns.TypeA, "phone", "10.1.2.3"))
	require.NoError(t, err)
	require.False(t, handled)
	require.Nil(t, res)
}

func TestPolicyProfileEngineLongestNetworkPrefixWins(t *testing.T) {
	engine, err := NewPolicyProfileEngine(PolicyProfileEngineConfig{
		DefaultProfileID: "default",
		Profiles: []PolicyProfile{
			{ID: "default"},
			{ID: "wide", Rules: []PolicyRule{{ID: "wide-block", Action: PolicyActionBlock, Match: PolicyMatch{Kind: PolicyMatchSuffix, Value: "example.org"}}}},
			{ID: "narrow", Rules: []PolicyRule{{ID: "narrow-allow", Action: PolicyActionAllow, Match: PolicyMatch{Kind: PolicyMatchSuffix, Value: "example.org"}}}},
		},
		Assignments: []PolicyAssignment{
			{ProfileID: "wide", Prefix: netip.MustParsePrefix("10.0.0.0/8")},
			{ProfileID: "narrow", Prefix: netip.MustParsePrefix("10.10.0.0/16")},
		},
	})
	require.NoError(t, err)

	res, handled, err := engine.Evaluate(context.Background(), policyTestRequest("www.example.org", dns.TypeA, "", "10.10.2.3"))
	require.NoError(t, err)
	require.False(t, handled)
	require.Nil(t, res)
}

func TestPolicyProfileEnginePriorityAllowsCustomExceptionOverServiceBlock(t *testing.T) {
	recorder := &policyDecisionRecorderStub{}
	engine, err := NewPolicyProfileEngine(PolicyProfileEngineConfig{
		DefaultProfileID: "default",
		Catalog:          PolicyCatalog{Services: map[string][]string{"video": {"video.example"}}},
		Profiles: []PolicyProfile{{
			ID: "default",
			Rules: []PolicyRule{
				{ID: "allow-school-video", Priority: 100, Action: PolicyActionAllow, Match: PolicyMatch{Kind: PolicyMatchExact, Value: "school.video.example"}},
				{ID: "block-video", Priority: 50, Action: PolicyActionBlock, Match: PolicyMatch{Kind: PolicyMatchService, Value: "video"}},
			},
		}},
		DecisionRecorder: recorder,
	})
	require.NoError(t, err)

	res, handled, err := engine.Evaluate(context.Background(), policyTestRequest("school.video.example", dns.TypeA, "student", "192.0.2.10"))
	require.NoError(t, err)
	require.False(t, handled)
	require.Nil(t, res)
	require.Len(t, recorder.decisions, 1)
	require.Equal(t, "allow-school-video", recorder.decisions[0].RuleID)
	require.Equal(t, "default", recorder.decisions[0].AssignmentScope)
}

func TestPolicyProfileEngineEqualPriorityUsesExactBeforeSuffix(t *testing.T) {
	engine, err := NewPolicyProfileEngine(PolicyProfileEngineConfig{
		DefaultProfileID: "default",
		Profiles: []PolicyProfile{{
			ID: "default",
			Rules: []PolicyRule{
				{ID: "suffix-block", Priority: 10, Action: PolicyActionBlock, Match: PolicyMatch{Kind: PolicyMatchSuffix, Value: "example.org"}},
				{ID: "exact-allow", Priority: 10, Action: PolicyActionAllow, Match: PolicyMatch{Kind: PolicyMatchExact, Value: "safe.example.org"}},
			},
		}},
	})
	require.NoError(t, err)

	_, handled, err := engine.Evaluate(context.Background(), policyTestRequest("safe.example.org", dns.TypeA, "", ""))
	require.NoError(t, err)
	require.False(t, handled)
}

func TestPolicyProfileEngineScheduledRule(t *testing.T) {
	monday2300 := time.Date(2026, 8, 31, 23, 0, 0, 0, time.UTC)
	engine, err := NewPolicyProfileEngine(PolicyProfileEngineConfig{
		DefaultProfileID: "default",
		Now:              func() time.Time { return monday2300 },
		Profiles: []PolicyProfile{{
			ID: "default",
			Rules: []PolicyRule{{
				ID:       "sleep-block",
				Action:   PolicyActionBlock,
				Match:    PolicyMatch{Kind: PolicyMatchSuffix, Value: "games.example"},
				Schedule: &PolicySchedule{Days: []time.Weekday{time.Monday}, StartMinute: 22 * 60, EndMinute: 6 * 60, Timezone: "UTC"},
			}},
		}},
	})
	require.NoError(t, err)

	res, handled, err := engine.Evaluate(context.Background(), policyTestRequest("play.games.example", dns.TypeA, "", ""))
	require.NoError(t, err)
	require.True(t, handled)
	require.Equal(t, dns.RcodeRefused, res.Message.Rcode)
}

func TestPolicyProfileEngineOvernightScheduleUsesPreviousDay(t *testing.T) {
	tuesday0100 := time.Date(2026, 9, 1, 1, 0, 0, 0, time.UTC)
	engine, err := NewPolicyProfileEngine(PolicyProfileEngineConfig{
		DefaultProfileID: "default",
		Now:              func() time.Time { return tuesday0100 },
		Profiles: []PolicyProfile{{
			ID: "default",
			Rules: []PolicyRule{{
				ID:       "sleep-block",
				Action:   PolicyActionBlock,
				Match:    PolicyMatch{Kind: PolicyMatchSuffix, Value: "games.example"},
				Schedule: &PolicySchedule{Days: []time.Weekday{time.Monday}, StartMinute: 22 * 60, EndMinute: 6 * 60, Timezone: "UTC"},
			}},
		}},
	})
	require.NoError(t, err)

	_, handled, err := engine.Evaluate(context.Background(), policyTestRequest("play.games.example", dns.TypeA, "", ""))
	require.NoError(t, err)
	require.True(t, handled)
}

func TestPolicyProfileEngineBlockNXDOMAIN(t *testing.T) {
	engine, err := NewPolicyProfileEngine(PolicyProfileEngineConfig{
		DefaultProfileID: "default",
		Profiles: []PolicyProfile{{ID: "default", Rules: []PolicyRule{{
			ID: "block", Action: PolicyActionBlock, BlockRcode: dns.RcodeNameError, Match: PolicyMatch{Kind: PolicyMatchExact, Value: "blocked.example"},
		}}}},
	})
	require.NoError(t, err)

	res, handled, err := engine.Evaluate(context.Background(), policyTestRequest("blocked.example", dns.TypeA, "", ""))
	require.NoError(t, err)
	require.True(t, handled)
	require.Equal(t, dns.RcodeNameError, res.Message.Rcode)
}

func TestPolicyProfileEngineAddressRewrite(t *testing.T) {
	engine, err := NewPolicyProfileEngine(PolicyProfileEngineConfig{
		DefaultProfileID: "default",
		Profiles: []PolicyProfile{{ID: "default", Rules: []PolicyRule{{
			ID: "rewrite", Action: PolicyActionRewrite, Match: PolicyMatch{Kind: PolicyMatchExact, Value: "portal.example"}, Rewrite: PolicyRewrite{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.44"), netip.MustParseAddr("2001:db8::44")}, TTL: 120},
		}}}},
	})
	require.NoError(t, err)

	res, handled, err := engine.Evaluate(context.Background(), policyTestRequest("portal.example", dns.TypeA, "", ""))
	require.NoError(t, err)
	require.True(t, handled)
	require.Len(t, res.Message.Answer, 1)
	a, ok := res.Message.Answer[0].(*dns.A)
	require.True(t, ok)
	require.Equal(t, "192.0.2.44", a.A.String())
	require.Equal(t, uint32(120), a.Hdr.Ttl)
}

func TestPolicyProfileEngineCNAMERewrite(t *testing.T) {
	engine, err := NewPolicyProfileEngine(PolicyProfileEngineConfig{
		DefaultProfileID: "default",
		Profiles: []PolicyProfile{{ID: "default", Rules: []PolicyRule{{
			ID: "rewrite", Action: PolicyActionRewrite, Match: PolicyMatch{Kind: PolicyMatchExact, Value: "alias.example"}, Rewrite: PolicyRewrite{CNAME: "target.example"},
		}}}},
	})
	require.NoError(t, err)

	res, handled, err := engine.Evaluate(context.Background(), policyTestRequest("alias.example", dns.TypeAAAA, "", ""))
	require.NoError(t, err)
	require.True(t, handled)
	require.Len(t, res.Message.Answer, 1)
	cname, ok := res.Message.Answer[0].(*dns.CNAME)
	require.True(t, ok)
	require.Equal(t, "target.example.", cname.Target)
}

func TestPolicyDecisionIsPrivacyMinimized(t *testing.T) {
	decision := PolicyDecision{
		ProfileID:       "family",
		RuleID:          "block-video",
		Action:          PolicyActionBlock,
		AssignmentScope: "client",
		MatchKind:       PolicyMatchService,
	}
	require.Equal(t, "family", decision.ProfileID)
	require.NotContains(t, decision.RuleID, "example.org")
}

func TestPolicyProfileEngineRejectsConflictingAssignments(t *testing.T) {
	_, err := NewPolicyProfileEngine(PolicyProfileEngineConfig{
		DefaultProfileID: "default",
		Profiles:         []PolicyProfile{{ID: "default"}, {ID: "other"}},
		Assignments: []PolicyAssignment{
			{ProfileID: "default", ClientID: "phone"},
			{ProfileID: "other", ClientID: "phone"},
		},
	})
	require.ErrorContains(t, err, "conflicting client policy assignment")
}
