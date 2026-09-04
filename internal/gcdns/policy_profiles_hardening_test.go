package gcdns

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestPolicyProfileEngineTrimsProfileReferences(t *testing.T) {
	engine, err := NewPolicyProfileEngine(PolicyProfileEngineConfig{
		DefaultProfileID: " default ",
		Profiles:         []PolicyProfile{{ID: " default "}},
		Assignments:      []PolicyAssignment{{ProfileID: " default ", ClientID: " phone "}},
	})
	require.NoError(t, err)

	res, handled, err := engine.Evaluate(context.Background(), policyTestRequest("example.org", dns.TypeA, "phone", ""))
	require.NoError(t, err)
	require.False(t, handled)
	require.Nil(t, res)
}

func TestPolicyProfileEngineRejectsNormalizedCatalogCollision(t *testing.T) {
	_, err := NewPolicyProfileEngine(PolicyProfileEngineConfig{
		DefaultProfileID: "default",
		Profiles:         []PolicyProfile{{ID: "default"}},
		Catalog: PolicyCatalog{Categories: map[string][]string{
			"Social":   {"social.example"},
			" social ": {"other.example"},
		}},
	})
	require.ErrorContains(t, err, "duplicate normalized catalog entry")
}

func TestPolicyProfileEngineSyntheticResultIsDNSSECIndeterminate(t *testing.T) {
	engine, err := NewPolicyProfileEngine(PolicyProfileEngineConfig{
		DefaultProfileID: "default",
		Profiles: []PolicyProfile{{ID: "default", Rules: []PolicyRule{{
			ID: "block", Action: PolicyActionBlock, Match: PolicyMatch{Kind: PolicyMatchExact, Value: "blocked.example"},
		}}}},
	})
	require.NoError(t, err)

	res, handled, err := engine.Evaluate(context.Background(), policyTestRequest("blocked.example", dns.TypeA, "", ""))
	require.NoError(t, err)
	require.True(t, handled)
	require.Equal(t, DNSSECIndeterminate, res.DNSSECStatus)
}
