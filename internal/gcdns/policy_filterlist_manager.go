package gcdns

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// PolicyFilterListSnapshotSource exposes only the already-authenticated,
// freshness-gated snapshot needed for managed list composition. A
// PolicyFilterListRefreshController satisfies this interface.
type PolicyFilterListSnapshotSource interface {
	UsableSnapshot(time.Time) (PolicyFilterListSnapshot, PolicyFilterListAvailability, bool)
}

// PolicyFilterListManagedSource binds one local managed-list identity to one
// immutable remote source identity. Required sources cannot be disabled; this
// prevents an administrative toggle from silently bypassing a fail-closed list.
type PolicyFilterListManagedSource struct {
	ID               string
	ExpectedSourceID string
	Enabled          bool
	Required         bool
	Priority         int
	Schedule         *PolicySchedule
	BlockRcode       int
	Source           PolicyFilterListSnapshotSource
}

// PolicyFilterListManagedState is a privacy-minimized composition status. It
// intentionally excludes source URLs, content, digests, signing keys, and
// acquisition errors.
type PolicyFilterListManagedState struct {
	ID             string
	Enabled        bool
	Required       bool
	Availability   PolicyFilterListAvailability
	ActiveSequence uint64
	RuleCount      int
}

// PolicyFilterListManager composes independently authenticated filter-list
// snapshots into ordinary Beacon policy rules. It owns no acquisition
// goroutines, listeners, or production activation path.
type PolicyFilterListManager struct {
	mu      sync.RWMutex
	sources []PolicyFilterListManagedSource
}

// NewPolicyFilterListManager validates and freezes the trust/source bindings
// used by managed composition. Source order in the input does not affect rule or
// status ordering.
func NewPolicyFilterListManager(sources []PolicyFilterListManagedSource) (*PolicyFilterListManager, error) {
	if len(sources) == 0 {
		return nil, errors.New("goreecloud dns: at least one managed filter-list source is required")
	}

	managed := make([]PolicyFilterListManagedSource, 0, len(sources))
	seenIDs := make(map[string]struct{}, len(sources))
	seenSourceIDs := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		id := strings.TrimSpace(source.ID)
		if id == "" {
			return nil, errors.New("goreecloud dns: managed filter-list ID is required")
		}
		if _, exists := seenIDs[id]; exists {
			return nil, fmt.Errorf("goreecloud dns: duplicate managed filter-list ID %q", id)
		}
		seenIDs[id] = struct{}{}

		expectedSourceID := strings.TrimSpace(source.ExpectedSourceID)
		if expectedSourceID == "" {
			return nil, fmt.Errorf("goreecloud dns: managed filter-list %q expected source ID is required", id)
		}
		if _, exists := seenSourceIDs[expectedSourceID]; exists {
			return nil, fmt.Errorf("goreecloud dns: duplicate managed filter-list source identity %q", expectedSourceID)
		}
		seenSourceIDs[expectedSourceID] = struct{}{}

		if source.Source == nil {
			return nil, fmt.Errorf("goreecloud dns: managed filter-list %q snapshot source is required", id)
		}
		if source.Required && !source.Enabled {
			return nil, fmt.Errorf("goreecloud dns: required managed filter-list %q cannot start disabled", id)
		}

		copy := source
		copy.ID = id
		copy.ExpectedSourceID = expectedSourceID
		copy.Schedule = clonePolicySchedule(source.Schedule)
		managed = append(managed, copy)
	}

	sort.Slice(managed, func(i, j int) bool {
		return managed[i].ID < managed[j].ID
	})
	return &PolicyFilterListManager{sources: managed}, nil
}

// SetEnabled changes the local administrative enablement of an optional list.
// Required sources cannot be disabled because that would turn a trust/freshness
// failure into a policy bypass.
func (m *PolicyFilterListManager) SetEnabled(id string, enabled bool) error {
	if m == nil {
		return errors.New("goreecloud dns: filter-list manager is required")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("goreecloud dns: managed filter-list ID is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.sources {
		if m.sources[i].ID != id {
			continue
		}
		if m.sources[i].Required && !enabled {
			return fmt.Errorf("goreecloud dns: required managed filter-list %q cannot be disabled", id)
		}
		m.sources[i].Enabled = enabled
		return nil
	}
	return fmt.Errorf("goreecloud dns: unknown managed filter-list %q", id)
}

// BuildRules composes all enabled usable snapshots into deterministic ordinary
// Beacon policy rules. Missing required sources fail closed and return no
// partial rules. Optional unavailable sources are explicitly skipped. A source
// identity mismatch always fails closed, even for an optional source.
func (m *PolicyFilterListManager) BuildRules(now time.Time) ([]PolicyRule, []PolicyFilterListManagedState, error) {
	if m == nil {
		return nil, nil, errors.New("goreecloud dns: filter-list manager is required")
	}

	sources := m.snapshotSources()
	states := make([]PolicyFilterListManagedState, 0, len(sources))
	rules := make([]PolicyRule, 0)
	for _, source := range sources {
		state := PolicyFilterListManagedState{
			ID:           source.ID,
			Enabled:      source.Enabled,
			Required:     source.Required,
			Availability: PolicyFilterListAvailabilityUnavailable,
		}
		if !source.Enabled {
			states = append(states, state)
			continue
		}

		snapshot, availability, ok := source.Source.UsableSnapshot(now)
		state.Availability = availability
		if !ok {
			states = append(states, state)
			if source.Required {
				return nil, states, fmt.Errorf("goreecloud dns: required managed filter-list %q is unavailable", source.ID)
			}
			continue
		}
		state.ActiveSequence = snapshot.Provenance.Sequence

		if snapshot.Provenance.SourceID != source.ExpectedSourceID {
			states = append(states, state)
			return nil, states, fmt.Errorf("goreecloud dns: managed filter-list %q source identity mismatch", source.ID)
		}

		compiled, err := BuildPolicyFilterListRules(PolicyFilterListConfig{
			ID:             source.ID,
			Priority:       source.Priority,
			Schedule:       source.Schedule,
			BlockRcode:     source.BlockRcode,
			ExpectedSHA256: snapshot.Provenance.ContentSHA256,
			Content:        snapshot.Content,
		})
		if err != nil {
			states = append(states, state)
			return nil, states, fmt.Errorf("goreecloud dns: managed filter-list %q compile: %w", source.ID, err)
		}
		state.RuleCount = len(compiled)
		states = append(states, state)
		rules = append(rules, compiled...)
	}

	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority > rules[j].Priority
		}
		return rules[i].ID < rules[j].ID
	})
	return rules, states, nil
}

func (m *PolicyFilterListManager) snapshotSources() []PolicyFilterListManagedSource {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]PolicyFilterListManagedSource, len(m.sources))
	for i, source := range m.sources {
		out[i] = source
		out[i].Schedule = clonePolicySchedule(source.Schedule)
	}
	return out
}
