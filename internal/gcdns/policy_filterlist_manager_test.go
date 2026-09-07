package gcdns

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"
)

type fakePolicyFilterListSnapshotSource struct {
	snapshot     PolicyFilterListSnapshot
	availability PolicyFilterListAvailability
	ok           bool
	calls        int
}

func (f *fakePolicyFilterListSnapshotSource) UsableSnapshot(time.Time) (PolicyFilterListSnapshot, PolicyFilterListAvailability, bool) {
	f.calls++
	return clonePolicyFilterListSnapshot(f.snapshot), f.availability, f.ok
}

func TestPolicyFilterListManagerBuildRulesDeterministicComposition(t *testing.T) {
	now := time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC)
	core := &fakePolicyFilterListSnapshotSource{
		snapshot:     managedFilterListSnapshot("core-source", 4, now, []byte("ads.example\n@@safe.example\n")),
		availability: PolicyFilterListAvailabilityFresh,
		ok:           true,
	}
	privacy := &fakePolicyFilterListSnapshotSource{
		snapshot:     managedFilterListSnapshot("privacy-source", 9, now, []byte("tracker.example\n")),
		availability: PolicyFilterListAvailabilityOfflineGrace,
		ok:           true,
	}

	manager, err := NewPolicyFilterListManager([]PolicyFilterListManagedSource{
		{
			ID:               "privacy",
			ExpectedSourceID: "privacy-source",
			Enabled:          true,
			Priority:         50,
			Source:           privacy,
		},
		{
			ID:               "core",
			ExpectedSourceID: "core-source",
			Enabled:          true,
			Required:         true,
			Priority:         100,
			Source:           core,
		},
	})
	if err != nil {
		t.Fatalf("NewPolicyFilterListManager() error = %v", err)
	}

	rules, states, err := manager.BuildRules(now)
	if err != nil {
		t.Fatalf("BuildRules() error = %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("BuildRules() rule count = %d, want 3", len(rules))
	}
	wantRuleIDs := []string{"core:allow:000001", "core:block:000001", "privacy:block:000001"}
	for i, want := range wantRuleIDs {
		if rules[i].ID != want {
			t.Fatalf("rules[%d].ID = %q, want %q", i, rules[i].ID, want)
		}
	}
	if rules[0].Priority != 101 || rules[1].Priority != 100 || rules[2].Priority != 50 {
		t.Fatalf("rule priorities = [%d %d %d], want [101 100 50]", rules[0].Priority, rules[1].Priority, rules[2].Priority)
	}
	if len(states) != 2 || states[0].ID != "core" || states[1].ID != "privacy" {
		t.Fatalf("state IDs = %#v, want sorted core/privacy", states)
	}
	if states[0].RuleCount != 2 || states[0].ActiveSequence != 4 || states[0].Availability != PolicyFilterListAvailabilityFresh {
		t.Fatalf("core state = %#v", states[0])
	}
	if states[1].RuleCount != 1 || states[1].ActiveSequence != 9 || states[1].Availability != PolicyFilterListAvailabilityOfflineGrace {
		t.Fatalf("privacy state = %#v", states[1])
	}
}

func TestPolicyFilterListManagerRequiredUnavailableFailsClosed(t *testing.T) {
	now := time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC)
	required := &fakePolicyFilterListSnapshotSource{availability: PolicyFilterListAvailabilityUnavailable}
	manager, err := NewPolicyFilterListManager([]PolicyFilterListManagedSource{{
		ID:               "required",
		ExpectedSourceID: "required-source",
		Enabled:          true,
		Required:         true,
		Source:           required,
	}})
	if err != nil {
		t.Fatalf("NewPolicyFilterListManager() error = %v", err)
	}

	rules, states, err := manager.BuildRules(now)
	if err == nil {
		t.Fatal("BuildRules() error = nil, want required-source failure")
	}
	if rules != nil {
		t.Fatalf("BuildRules() returned partial rules on required failure: %#v", rules)
	}
	if len(states) != 1 || states[0].Availability != PolicyFilterListAvailabilityUnavailable {
		t.Fatalf("states = %#v", states)
	}
}

func TestPolicyFilterListManagerOptionalUnavailableIsSkipped(t *testing.T) {
	now := time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC)
	required := &fakePolicyFilterListSnapshotSource{
		snapshot:     managedFilterListSnapshot("required-source", 2, now, []byte("ads.example\n")),
		availability: PolicyFilterListAvailabilityFresh,
		ok:           true,
	}
	optional := &fakePolicyFilterListSnapshotSource{availability: PolicyFilterListAvailabilityUnavailable}
	manager, err := NewPolicyFilterListManager([]PolicyFilterListManagedSource{
		{ID: "required", ExpectedSourceID: "required-source", Enabled: true, Required: true, Source: required},
		{ID: "optional", ExpectedSourceID: "optional-source", Enabled: true, Source: optional},
	})
	if err != nil {
		t.Fatalf("NewPolicyFilterListManager() error = %v", err)
	}

	rules, states, err := manager.BuildRules(now)
	if err != nil {
		t.Fatalf("BuildRules() error = %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "required:block:000001" {
		t.Fatalf("rules = %#v", rules)
	}
	if len(states) != 2 || states[0].ID != "optional" || states[0].RuleCount != 0 || states[1].ID != "required" {
		t.Fatalf("states = %#v", states)
	}
}

func TestPolicyFilterListManagerEnableDisableOptionalSource(t *testing.T) {
	now := time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC)
	optional := &fakePolicyFilterListSnapshotSource{
		snapshot:     managedFilterListSnapshot("optional-source", 1, now, []byte("ads.example\n")),
		availability: PolicyFilterListAvailabilityFresh,
		ok:           true,
	}
	manager, err := NewPolicyFilterListManager([]PolicyFilterListManagedSource{{
		ID:               "optional",
		ExpectedSourceID: "optional-source",
		Enabled:          false,
		Source:           optional,
	}})
	if err != nil {
		t.Fatalf("NewPolicyFilterListManager() error = %v", err)
	}

	rules, states, err := manager.BuildRules(now)
	if err != nil {
		t.Fatalf("BuildRules() disabled error = %v", err)
	}
	if len(rules) != 0 || optional.calls != 0 || len(states) != 1 || states[0].Enabled {
		t.Fatalf("disabled composition rules=%#v calls=%d states=%#v", rules, optional.calls, states)
	}

	err = manager.SetEnabled("optional", true)
	if err != nil {
		t.Fatalf("SetEnabled(true) error = %v", err)
	}
	rules, states, err = manager.BuildRules(now)
	if err != nil {
		t.Fatalf("BuildRules() enabled error = %v", err)
	}
	if len(rules) != 1 || optional.calls != 1 || !states[0].Enabled {
		t.Fatalf("enabled composition rules=%#v calls=%d states=%#v", rules, optional.calls, states)
	}
}

func TestPolicyFilterListManagerRejectsRequiredDisableAndSourceMismatch(t *testing.T) {
	now := time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC)
	required := &fakePolicyFilterListSnapshotSource{
		snapshot:     managedFilterListSnapshot("different-source", 1, now, []byte("ads.example\n")),
		availability: PolicyFilterListAvailabilityFresh,
		ok:           true,
	}
	manager, err := NewPolicyFilterListManager([]PolicyFilterListManagedSource{{
		ID:               "required",
		ExpectedSourceID: "required-source",
		Enabled:          true,
		Required:         true,
		Source:           required,
	}})
	if err != nil {
		t.Fatalf("NewPolicyFilterListManager() error = %v", err)
	}
	if err := manager.SetEnabled("required", false); err == nil {
		t.Fatal("SetEnabled(false) error = nil, want required-list rejection")
	}
	if rules, _, err := manager.BuildRules(now); err == nil || rules != nil {
		t.Fatalf("BuildRules() rules=%#v error=%v, want fail-closed source mismatch", rules, err)
	}
}

func TestPolicyFilterListManagerRejectsDuplicateBindings(t *testing.T) {
	source := &fakePolicyFilterListSnapshotSource{}
	if _, err := NewPolicyFilterListManager([]PolicyFilterListManagedSource{
		{ID: "same", ExpectedSourceID: "one", Source: source},
		{ID: "same", ExpectedSourceID: "two", Source: source},
	}); err == nil {
		t.Fatal("duplicate managed ID error = nil")
	}
	if _, err := NewPolicyFilterListManager([]PolicyFilterListManagedSource{
		{ID: "one", ExpectedSourceID: "same-source", Source: source},
		{ID: "two", ExpectedSourceID: "same-source", Source: source},
	}); err == nil {
		t.Fatal("duplicate source identity error = nil")
	}
	if _, err := NewPolicyFilterListManager([]PolicyFilterListManagedSource{{
		ID:               "required",
		ExpectedSourceID: "required-source",
		Required:         true,
		Enabled:          false,
		Source:           source,
	}}); err == nil {
		t.Fatal("required disabled constructor error = nil")
	}
}

func managedFilterListSnapshot(sourceID string, sequence uint64, now time.Time, content []byte) PolicyFilterListSnapshot {
	digest := sha256.Sum256(content)
	return PolicyFilterListSnapshot{
		Provenance: PolicyFilterListProvenance{
			SourceID:      sourceID,
			Sequence:      sequence,
			IssuedAt:      now.Add(-time.Hour),
			ExpiresAt:     now.Add(time.Hour),
			ContentSHA256: fmt.Sprintf("%x", digest),
		},
		Content: append([]byte(nil), content...),
	}
}
