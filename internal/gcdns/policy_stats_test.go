package gcdns

import (
	"context"
	"reflect"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolicyDecisionStatsAggregatesDeterministically(t *testing.T) {
	stats := NewPolicyDecisionStats()
	decision := PolicyDecision{
		ProfileID:       "family",
		RuleID:          "block-video",
		Action:          PolicyActionBlock,
		AssignmentScope: "client",
		MatchKind:       PolicyMatchService,
	}
	stats.RecordPolicyDecision(context.Background(), decision)
	stats.RecordPolicyDecision(context.Background(), decision)
	stats.RecordPolicyDecision(context.Background(), PolicyDecision{
		ProfileID:       "default",
		RuleID:          "allow-school",
		Action:          PolicyActionAllow,
		AssignmentScope: "default",
		MatchKind:       PolicyMatchExact,
	})

	got := stats.Snapshot()
	require.Len(t, got, 2)
	require.Equal(t, "default", got[0].ProfileID)
	require.Equal(t, uint64(1), got[0].Count)
	require.Equal(t, "family", got[1].ProfileID)
	require.Equal(t, uint64(2), got[1].Count)
}

func TestPolicyDecisionStatsConcurrentRecording(t *testing.T) {
	stats := NewPolicyDecisionStats()
	decision := PolicyDecision{
		ProfileID:       "iot",
		RuleID:          "block-telemetry",
		Action:          PolicyActionBlock,
		AssignmentScope: "network",
		MatchKind:       PolicyMatchCategory,
	}

	const goroutines = 16
	const perGoroutine = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range perGoroutine {
				stats.RecordPolicyDecision(context.Background(), decision)
			}
		}()
	}
	wg.Wait()

	got := stats.Snapshot()
	require.Len(t, got, 1)
	require.Equal(t, uint64(goroutines*perGoroutine), got[0].Count)
}

func TestPolicyDecisionStatsReset(t *testing.T) {
	stats := NewPolicyDecisionStats()
	stats.RecordPolicyDecision(context.Background(), PolicyDecision{ProfileID: "default", RuleID: "block", Action: PolicyActionBlock})
	require.NotEmpty(t, stats.Snapshot())
	stats.Reset()
	require.Empty(t, stats.Snapshot())
}

func TestPolicyDecisionStatHasNoRawActivityFields(t *testing.T) {
	typ := reflect.TypeOf(PolicyDecisionStat{})
	for _, forbidden := range []string{"QName", "QueryName", "ClientIP", "ClientID", "Domain", "MatchValue"} {
		_, exists := typ.FieldByName(forbidden)
		require.Falsef(t, exists, "privacy-safe policy stat must not expose %s", forbidden)
	}
}
