package gcdns

import (
	"context"
	"sort"
	"sync"
)

// PolicyDecisionStat is one aggregate, privacy-safe policy counter.  It has no
// raw query name, client IP address, client identifier, or matched domain value.
type PolicyDecisionStat struct {
	ProfileID       string
	RuleID          string
	Action          PolicyAction
	AssignmentScope string
	MatchKind       PolicyMatchKind
	Count           uint64
}

// PolicyDecisionStats aggregates PolicyDecision records without retaining raw
// DNS activity.  It is suitable as a local source for Beacon Insights counters.
type PolicyDecisionStats struct {
	mu     sync.RWMutex
	counts map[policyDecisionStatKey]uint64
}

type policyDecisionStatKey struct {
	profileID       string
	ruleID          string
	action          PolicyAction
	assignmentScope string
	matchKind       PolicyMatchKind
}

// NewPolicyDecisionStats constructs an empty policy statistics recorder.
func NewPolicyDecisionStats() *PolicyDecisionStats {
	return &PolicyDecisionStats{counts: make(map[policyDecisionStatKey]uint64)}
}

// RecordPolicyDecision implements PolicyDecisionRecorder.
func (s *PolicyDecisionStats) RecordPolicyDecision(_ context.Context, decision PolicyDecision) {
	if s == nil {
		return
	}
	key := policyDecisionStatKey{
		profileID:       decision.ProfileID,
		ruleID:          decision.RuleID,
		action:          decision.Action,
		assignmentScope: decision.AssignmentScope,
		matchKind:       decision.MatchKind,
	}
	s.mu.Lock()
	if s.counts == nil {
		s.counts = make(map[policyDecisionStatKey]uint64)
	}
	s.counts[key]++
	s.mu.Unlock()
}

// Snapshot returns deterministic aggregate counters without exposing mutable
// internal state.
func (s *PolicyDecisionStats) Snapshot() []PolicyDecisionStat {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	out := make([]PolicyDecisionStat, 0, len(s.counts))
	for key, count := range s.counts {
		out = append(out, PolicyDecisionStat{
			ProfileID:       key.profileID,
			RuleID:          key.ruleID,
			Action:          key.action,
			AssignmentScope: key.assignmentScope,
			MatchKind:       key.matchKind,
			Count:           count,
		})
	}
	s.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].ProfileID != out[j].ProfileID {
			return out[i].ProfileID < out[j].ProfileID
		}
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		if out[i].Action != out[j].Action {
			return out[i].Action < out[j].Action
		}
		if out[i].AssignmentScope != out[j].AssignmentScope {
			return out[i].AssignmentScope < out[j].AssignmentScope
		}
		return out[i].MatchKind < out[j].MatchKind
	})
	return out
}

// Reset removes only aggregate policy counters.  It does not alter profiles,
// assignments, policy state, cache state, or DNS configuration.
func (s *PolicyDecisionStats) Reset() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.counts = make(map[policyDecisionStatKey]uint64)
	s.mu.Unlock()
}

var _ PolicyDecisionRecorder = (*PolicyDecisionStats)(nil)
