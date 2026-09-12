package gcdns

import (
	"strings"
	"testing"
	"time"
)

type managedConfigRecoverySnapshotSource struct{}

func (*managedConfigRecoverySnapshotSource) UsableSnapshot(time.Time) (PolicyFilterListSnapshot, PolicyFilterListAvailability, bool) {
	return PolicyFilterListSnapshot{}, PolicyFilterListAvailabilityUnavailable, false
}

func TestBuildPolicyFilterListManagedConfigRecoveryPointDeterministic(t *testing.T) {
	now := time.Date(2026, time.September, 11, 20, 0, 0, 0, time.UTC)
	firstSource := &managedConfigRecoverySnapshotSource{}
	secondSource := &managedConfigRecoverySnapshotSource{}

	first := mustManagedConfigRecoveryManager(t, []PolicyFilterListManagedSource{
		{ID: "privacy", ExpectedSourceID: "privacy-source", Enabled: true, Priority: 20, Source: firstSource},
		{ID: "core", ExpectedSourceID: "core-source", Enabled: true, Required: true, Priority: 100, Source: secondSource},
	})
	second := mustManagedConfigRecoveryManager(t, []PolicyFilterListManagedSource{
		{ID: "core", ExpectedSourceID: "core-source", Enabled: true, Required: true, Priority: 100, Source: secondSource},
		{ID: "privacy", ExpectedSourceID: "privacy-source", Enabled: true, Priority: 20, Source: firstSource},
	})

	one, err := BuildPolicyFilterListManagedConfigRecoveryPoint(first, 7, now)
	if err != nil {
		t.Fatalf("BuildPolicyFilterListManagedConfigRecoveryPoint(first): %v", err)
	}
	two, err := BuildPolicyFilterListManagedConfigRecoveryPoint(second, 7, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("BuildPolicyFilterListManagedConfigRecoveryPoint(second): %v", err)
	}
	if one.StateFingerprintSHA256 != two.StateFingerprintSHA256 {
		t.Fatalf("fingerprint depends on source ordering: %q != %q", one.StateFingerprintSHA256, two.StateFingerprintSHA256)
	}
	if got := one.Sources[0].ID; got != "core" {
		t.Fatalf("first canonical source = %q, want core", got)
	}
}

func TestStagePolicyFilterListManagedConfigRecoveryPointPreservesRuntimeSourceAndDoesNotMutateCurrent(t *testing.T) {
	now := time.Date(2026, time.September, 11, 20, 5, 0, 0, time.UTC)
	coreRuntime := &managedConfigRecoverySnapshotSource{}
	privacyRuntime := &managedConfigRecoverySnapshotSource{}
	current := mustManagedConfigRecoveryManager(t, []PolicyFilterListManagedSource{
		{ID: "core", ExpectedSourceID: "core-source", Enabled: true, Required: true, Priority: 100, Source: coreRuntime},
		{ID: "privacy", ExpectedSourceID: "privacy-source", Enabled: true, Priority: 10, Source: privacyRuntime},
	})

	desired := mustManagedConfigRecoveryManager(t, []PolicyFilterListManagedSource{
		{ID: "core", ExpectedSourceID: "core-source", Enabled: true, Required: true, Priority: 120, BlockRcode: 5, Source: &managedConfigRecoverySnapshotSource{}},
		{ID: "privacy", ExpectedSourceID: "privacy-source", Enabled: false, Priority: 25, BlockRcode: 3, Source: &managedConfigRecoverySnapshotSource{}},
	})
	recovery, err := BuildPolicyFilterListManagedConfigRecoveryPoint(desired, 9, now)
	if err != nil {
		t.Fatalf("build recovery: %v", err)
	}

	candidate, err := StagePolicyFilterListManagedConfigRecoveryPoint(current, 8, recovery, recovery.StateFingerprintSHA256)
	if err != nil {
		t.Fatalf("stage recovery: %v", err)
	}

	candidateByID := managedConfigRecoverySourcesByID(candidate)
	if candidateByID["core"].Source != coreRuntime || candidateByID["privacy"].Source != privacyRuntime {
		t.Fatal("staged recovery replaced locally accepted runtime source objects")
	}
	if candidateByID["privacy"].Enabled {
		t.Fatal("staged recovery did not restore optional source enablement")
	}
	if candidateByID["core"].Priority != 120 || candidateByID["core"].BlockRcode != 5 {
		t.Fatalf("core operational configuration was not restored: %+v", candidateByID["core"])
	}

	currentByID := managedConfigRecoverySourcesByID(current.snapshotSources())
	if !currentByID["privacy"].Enabled || currentByID["privacy"].Priority != 10 {
		t.Fatalf("staging mutated current manager: %+v", currentByID["privacy"])
	}
}

func TestStagePolicyFilterListManagedConfigRecoveryPointRejectsOlderRevision(t *testing.T) {
	manager := mustManagedConfigRecoveryManager(t, []PolicyFilterListManagedSource{
		{ID: "core", ExpectedSourceID: "core-source", Enabled: true, Required: true, Source: &managedConfigRecoverySnapshotSource{}},
	})
	recovery, err := BuildPolicyFilterListManagedConfigRecoveryPoint(manager, 3, time.Now().UTC())
	if err != nil {
		t.Fatalf("build recovery: %v", err)
	}
	_, err = StagePolicyFilterListManagedConfigRecoveryPoint(manager, 4, recovery, recovery.StateFingerprintSHA256)
	if err == nil || !strings.Contains(err.Error(), "older than current") {
		t.Fatalf("expected revision rollback rejection, got %v", err)
	}
}

func TestStagePolicyFilterListManagedConfigRecoveryPointRejectsIndependentEvidenceMismatch(t *testing.T) {
	manager := mustManagedConfigRecoveryManager(t, []PolicyFilterListManagedSource{
		{ID: "core", ExpectedSourceID: "core-source", Enabled: true, Required: true, Source: &managedConfigRecoverySnapshotSource{}},
	})
	recovery, err := BuildPolicyFilterListManagedConfigRecoveryPoint(manager, 4, time.Now().UTC())
	if err != nil {
		t.Fatalf("build recovery: %v", err)
	}
	_, err = StagePolicyFilterListManagedConfigRecoveryPoint(manager, 4, recovery, strings.Repeat("0", 64))
	if err == nil || !strings.Contains(err.Error(), "evidence fingerprint mismatch") {
		t.Fatalf("expected evidence mismatch, got %v", err)
	}
}

func TestStagePolicyFilterListManagedConfigRecoveryPointRejectsSourceIdentityRebind(t *testing.T) {
	manager := mustManagedConfigRecoveryManager(t, []PolicyFilterListManagedSource{
		{ID: "core", ExpectedSourceID: "core-source", Enabled: true, Required: true, Source: &managedConfigRecoverySnapshotSource{}},
	})
	recovery, err := BuildPolicyFilterListManagedConfigRecoveryPoint(manager, 5, time.Now().UTC())
	if err != nil {
		t.Fatalf("build recovery: %v", err)
	}
	recovery.Sources[0].ExpectedSourceID = "attacker-controlled-source"
	recovery.StateFingerprintSHA256 = mustManagedConfigRecoveryFingerprint(t, recovery.Revision, recovery.Sources)

	_, err = StagePolicyFilterListManagedConfigRecoveryPoint(manager, 4, recovery, recovery.StateFingerprintSHA256)
	if err == nil || !strings.Contains(err.Error(), "rebinds source identity") {
		t.Fatalf("expected source rebind rejection, got %v", err)
	}
}

func TestStagePolicyFilterListManagedConfigRecoveryPointRejectsChangedSourceSet(t *testing.T) {
	manager := mustManagedConfigRecoveryManager(t, []PolicyFilterListManagedSource{
		{ID: "core", ExpectedSourceID: "core-source", Enabled: true, Required: true, Source: &managedConfigRecoverySnapshotSource{}},
		{ID: "privacy", ExpectedSourceID: "privacy-source", Enabled: true, Source: &managedConfigRecoverySnapshotSource{}},
	})
	recovery, err := BuildPolicyFilterListManagedConfigRecoveryPoint(manager, 6, time.Now().UTC())
	if err != nil {
		t.Fatalf("build recovery: %v", err)
	}
	recovery.Sources = recovery.Sources[:1]
	recovery.StateFingerprintSHA256 = mustManagedConfigRecoveryFingerprint(t, recovery.Revision, recovery.Sources)

	_, err = StagePolicyFilterListManagedConfigRecoveryPoint(manager, 5, recovery, recovery.StateFingerprintSHA256)
	if err == nil || !strings.Contains(err.Error(), "changes the accepted source set") {
		t.Fatalf("expected source-set rejection, got %v", err)
	}
}

func TestStagePolicyFilterListManagedConfigRecoveryPointRejectsRequiredSourceDisable(t *testing.T) {
	manager := mustManagedConfigRecoveryManager(t, []PolicyFilterListManagedSource{
		{ID: "core", ExpectedSourceID: "core-source", Enabled: true, Required: true, Source: &managedConfigRecoverySnapshotSource{}},
	})
	recovery, err := BuildPolicyFilterListManagedConfigRecoveryPoint(manager, 7, time.Now().UTC())
	if err != nil {
		t.Fatalf("build recovery: %v", err)
	}
	recovery.Sources[0].Enabled = false

	_, err = StagePolicyFilterListManagedConfigRecoveryPoint(manager, 6, recovery, recovery.StateFingerprintSHA256)
	if err == nil || !strings.Contains(err.Error(), "cannot be disabled") {
		t.Fatalf("expected required-source disable rejection, got %v", err)
	}
}

func mustManagedConfigRecoveryManager(t *testing.T, sources []PolicyFilterListManagedSource) *PolicyFilterListManager {
	t.Helper()
	manager, err := NewPolicyFilterListManager(sources)
	if err != nil {
		t.Fatalf("NewPolicyFilterListManager(): %v", err)
	}
	return manager
}

func mustManagedConfigRecoveryFingerprint(t *testing.T, revision uint64, sources []PolicyFilterListManagedConfigRecoverySource) string {
	t.Helper()
	fingerprint, err := policyFilterListManagedConfigRecoveryFingerprint(revision, sources)
	if err != nil {
		t.Fatalf("recovery fingerprint: %v", err)
	}
	return fingerprint
}

func managedConfigRecoverySourcesByID(sources []PolicyFilterListManagedSource) map[string]PolicyFilterListManagedSource {
	byID := make(map[string]PolicyFilterListManagedSource, len(sources))
	for _, source := range sources {
		byID[source.ID] = source
	}
	return byID
}
