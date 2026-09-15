package gcdns

import (
	"strings"
	"testing"
	"time"
)

func TestBuildPolicyFilterListRecoveryBundleDeterministic(t *testing.T) {
	now := time.Date(2026, time.September, 15, 12, 0, 0, 0, time.UTC)
	trustedState := BootstrapPolicyFilterListTrustedKeyState(now.Add(-2 * time.Hour))
	trusted, err := BuildPolicyFilterListTrustedKeyRecoveryPoint(trustedState, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("build trusted-key recovery: %v", err)
	}
	manager := mustManagedConfigRecoveryManager(t, []PolicyFilterListManagedSource{
		{ID: "privacy", ExpectedSourceID: "privacy-source", Enabled: true, Priority: 20, Source: &managedConfigRecoverySnapshotSource{}},
		{ID: "core", ExpectedSourceID: "core-source", Enabled: true, Required: true, Priority: 100, Source: &managedConfigRecoverySnapshotSource{}},
	})
	managed, err := BuildPolicyFilterListManagedConfigRecoveryPoint(manager, 4, now.Add(-30*time.Minute))
	if err != nil {
		t.Fatalf("build managed-config recovery: %v", err)
	}

	one, err := BuildPolicyFilterListRecoveryBundle(trusted, managed, now)
	if err != nil {
		t.Fatalf("BuildPolicyFilterListRecoveryBundle(one): %v", err)
	}
	two, err := BuildPolicyFilterListRecoveryBundle(trusted, managed, now)
	if err != nil {
		t.Fatalf("BuildPolicyFilterListRecoveryBundle(two): %v", err)
	}
	if one.StateFingerprintSHA256 != two.StateFingerprintSHA256 {
		t.Fatalf("bundle fingerprint is not deterministic: %q != %q", one.StateFingerprintSHA256, two.StateFingerprintSHA256)
	}
	if one.ManagedConfig.Sources[0].ID != "core" {
		t.Fatalf("managed sources are not canonical: first source = %q", one.ManagedConfig.Sources[0].ID)
	}
}

func TestStagePolicyFilterListRecoveryBundleStagesBothCandidatesWithoutMutation(t *testing.T) {
	now := time.Date(2026, time.September, 15, 12, 10, 0, 0, time.UTC)
	currentTrusted := BootstrapPolicyFilterListTrustedKeyState(now.Add(-3 * time.Hour))
	trustedRecovery, err := BuildPolicyFilterListTrustedKeyRecoveryPoint(currentTrusted, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("build trusted-key recovery: %v", err)
	}

	coreRuntime := &managedConfigRecoverySnapshotSource{}
	privacyRuntime := &managedConfigRecoverySnapshotSource{}
	currentManager := mustManagedConfigRecoveryManager(t, []PolicyFilterListManagedSource{
		{ID: "core", ExpectedSourceID: "core-source", Enabled: true, Required: true, Priority: 100, Source: coreRuntime},
		{ID: "privacy", ExpectedSourceID: "privacy-source", Enabled: true, Priority: 10, Source: privacyRuntime},
	})
	desiredManager := mustManagedConfigRecoveryManager(t, []PolicyFilterListManagedSource{
		{ID: "core", ExpectedSourceID: "core-source", Enabled: true, Required: true, Priority: 120, BlockRcode: 5, Source: &managedConfigRecoverySnapshotSource{}},
		{ID: "privacy", ExpectedSourceID: "privacy-source", Enabled: false, Priority: 25, BlockRcode: 3, Source: &managedConfigRecoverySnapshotSource{}},
	})
	managedRecovery, err := BuildPolicyFilterListManagedConfigRecoveryPoint(desiredManager, 9, now.Add(-45*time.Minute))
	if err != nil {
		t.Fatalf("build managed-config recovery: %v", err)
	}
	bundle, err := BuildPolicyFilterListRecoveryBundle(trustedRecovery, managedRecovery, now)
	if err != nil {
		t.Fatalf("build bundle: %v", err)
	}

	candidate, err := StagePolicyFilterListRecoveryBundle(currentTrusted, currentManager, 8, bundle, bundle.StateFingerprintSHA256)
	if err != nil {
		t.Fatalf("stage bundle: %v", err)
	}
	if candidate.ManagedConfigRevision != 9 {
		t.Fatalf("candidate managed revision = %d, want 9", candidate.ManagedConfigRevision)
	}
	candidateByID := managedConfigRecoverySourcesByID(candidate.ManagedSources)
	if candidateByID["core"].Source != coreRuntime || candidateByID["privacy"].Source != privacyRuntime {
		t.Fatal("bundle staging replaced locally accepted runtime source objects")
	}
	if candidateByID["privacy"].Enabled {
		t.Fatal("bundle staging did not restore optional source enablement")
	}
	if candidateByID["core"].Priority != 120 || candidateByID["core"].BlockRcode != 5 {
		t.Fatalf("bundle staging did not restore managed configuration: %+v", candidateByID["core"])
	}
	if candidate.TrustedKeys.Schema != currentTrusted.Schema || candidate.TrustedKeys.UpdatedAt != currentTrusted.UpdatedAt {
		t.Fatalf("unexpected trusted-key candidate: %+v", candidate.TrustedKeys)
	}

	currentByID := managedConfigRecoverySourcesByID(currentManager.snapshotSources())
	if currentByID["core"].Priority != 100 || !currentByID["privacy"].Enabled {
		t.Fatalf("bundle staging mutated current manager: %+v", currentByID)
	}
}

func TestStagePolicyFilterListRecoveryBundleRejectsMixedRecoveryComponents(t *testing.T) {
	now := time.Date(2026, time.September, 15, 12, 20, 0, 0, time.UTC)
	trustedState := BootstrapPolicyFilterListTrustedKeyState(now.Add(-2 * time.Hour))
	trusted, err := BuildPolicyFilterListTrustedKeyRecoveryPoint(trustedState, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("build trusted-key recovery: %v", err)
	}
	current := mustManagedConfigRecoveryManager(t, []PolicyFilterListManagedSource{
		{ID: "core", ExpectedSourceID: "core-source", Enabled: true, Required: true, Priority: 100, Source: &managedConfigRecoverySnapshotSource{}},
	})
	firstDesired := mustManagedConfigRecoveryManager(t, []PolicyFilterListManagedSource{
		{ID: "core", ExpectedSourceID: "core-source", Enabled: true, Required: true, Priority: 110, Source: &managedConfigRecoverySnapshotSource{}},
	})
	secondDesired := mustManagedConfigRecoveryManager(t, []PolicyFilterListManagedSource{
		{ID: "core", ExpectedSourceID: "core-source", Enabled: true, Required: true, Priority: 130, Source: &managedConfigRecoverySnapshotSource{}},
	})
	firstManaged, err := BuildPolicyFilterListManagedConfigRecoveryPoint(firstDesired, 2, now.Add(-40*time.Minute))
	if err != nil {
		t.Fatalf("build first managed recovery: %v", err)
	}
	secondManaged, err := BuildPolicyFilterListManagedConfigRecoveryPoint(secondDesired, 3, now.Add(-30*time.Minute))
	if err != nil {
		t.Fatalf("build second managed recovery: %v", err)
	}
	bundle, err := BuildPolicyFilterListRecoveryBundle(trusted, firstManaged, now)
	if err != nil {
		t.Fatalf("build bundle: %v", err)
	}

	mixed := bundle
	mixed.ManagedConfig = secondManaged
	_, err = StagePolicyFilterListRecoveryBundle(trustedState, current, 1, mixed, bundle.StateFingerprintSHA256)
	if err == nil || !strings.Contains(err.Error(), "bundle state fingerprint mismatch") {
		t.Fatalf("expected mixed-component fingerprint rejection, got %v", err)
	}
}

func TestStagePolicyFilterListRecoveryBundleRejectsIndependentEvidenceMismatch(t *testing.T) {
	now := time.Date(2026, time.September, 15, 12, 30, 0, 0, time.UTC)
	trustedState := BootstrapPolicyFilterListTrustedKeyState(now.Add(-2 * time.Hour))
	trusted, err := BuildPolicyFilterListTrustedKeyRecoveryPoint(trustedState, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("build trusted-key recovery: %v", err)
	}
	manager := mustManagedConfigRecoveryManager(t, []PolicyFilterListManagedSource{
		{ID: "core", ExpectedSourceID: "core-source", Enabled: true, Required: true, Source: &managedConfigRecoverySnapshotSource{}},
	})
	managed, err := BuildPolicyFilterListManagedConfigRecoveryPoint(manager, 2, now.Add(-30*time.Minute))
	if err != nil {
		t.Fatalf("build managed-config recovery: %v", err)
	}
	bundle, err := BuildPolicyFilterListRecoveryBundle(trusted, managed, now)
	if err != nil {
		t.Fatalf("build bundle: %v", err)
	}

	_, err = StagePolicyFilterListRecoveryBundle(trustedState, manager, 1, bundle, strings.Repeat("0", 64))
	if err == nil || !strings.Contains(err.Error(), "bundle evidence fingerprint mismatch") {
		t.Fatalf("expected independent evidence mismatch, got %v", err)
	}
}

func TestStagePolicyFilterListRecoveryBundlePreservesManagedRevisionRollbackGate(t *testing.T) {
	now := time.Date(2026, time.September, 15, 12, 40, 0, 0, time.UTC)
	trustedState := BootstrapPolicyFilterListTrustedKeyState(now.Add(-2 * time.Hour))
	trusted, err := BuildPolicyFilterListTrustedKeyRecoveryPoint(trustedState, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("build trusted-key recovery: %v", err)
	}
	manager := mustManagedConfigRecoveryManager(t, []PolicyFilterListManagedSource{
		{ID: "core", ExpectedSourceID: "core-source", Enabled: true, Required: true, Source: &managedConfigRecoverySnapshotSource{}},
	})
	managed, err := BuildPolicyFilterListManagedConfigRecoveryPoint(manager, 3, now.Add(-30*time.Minute))
	if err != nil {
		t.Fatalf("build managed-config recovery: %v", err)
	}
	bundle, err := BuildPolicyFilterListRecoveryBundle(trusted, managed, now)
	if err != nil {
		t.Fatalf("build bundle: %v", err)
	}

	_, err = StagePolicyFilterListRecoveryBundle(trustedState, manager, 4, bundle, bundle.StateFingerprintSHA256)
	if err == nil || !strings.Contains(err.Error(), "older than current configuration") {
		t.Fatalf("expected managed revision rollback rejection, got %v", err)
	}
}

func TestBuildPolicyFilterListRecoveryBundleRejectsFutureComponent(t *testing.T) {
	now := time.Date(2026, time.September, 15, 12, 50, 0, 0, time.UTC)
	trustedState := BootstrapPolicyFilterListTrustedKeyState(now.Add(-time.Hour))
	trusted, err := BuildPolicyFilterListTrustedKeyRecoveryPoint(trustedState, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("build trusted-key recovery: %v", err)
	}
	manager := mustManagedConfigRecoveryManager(t, []PolicyFilterListManagedSource{
		{ID: "core", ExpectedSourceID: "core-source", Enabled: true, Required: true, Source: &managedConfigRecoverySnapshotSource{}},
	})
	managed, err := BuildPolicyFilterListManagedConfigRecoveryPoint(manager, 2, now)
	if err != nil {
		t.Fatalf("build managed-config recovery: %v", err)
	}

	_, err = BuildPolicyFilterListRecoveryBundle(trusted, managed, now)
	if err == nil || !strings.Contains(err.Error(), "predates a protected component") {
		t.Fatalf("expected future component rejection, got %v", err)
	}
}
