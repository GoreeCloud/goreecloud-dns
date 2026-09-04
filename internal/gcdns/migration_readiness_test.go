package gcdns

import (
	"strings"
	"testing"
	"time"
)

func TestEvaluateMigrationReadinessRequiresEveryGate(t *testing.T) {
	evidence := completeMigrationEvidenceForTest()
	evidence.RestartFailureValidated = false
	evidence.ManagerIntegrationValidated = false
	evidence.EverkeepValidated = false
	evidence.MeshCoordinationValidated = false
	evidence.IdentityIntegrationValidated = false

	decision, err := EvaluateMigrationReadiness(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if decision.EligibleForMigrationRehearsal {
		t.Fatal("incomplete Beacon evidence unexpectedly eligible for migration rehearsal")
	}
	if decision.ProductionCutoverAuthorized {
		t.Fatal("Beacon readiness decision unexpectedly authorized production cutover")
	}
	want := []string{
		"restart_failure_validated",
		"manager_integration_validated",
		"everkeep_validated",
		"mesh_coordination_validated",
		"identity_integration_validated",
	}
	if len(decision.MissingGates) != len(want) {
		t.Fatalf("missing gates = %v, want %v", decision.MissingGates, want)
	}
	for i := range want {
		if decision.MissingGates[i] != want[i] {
			t.Fatalf("missing gates = %v, want %v", decision.MissingGates, want)
		}
	}
}

func TestEvaluateMigrationReadinessAcceptsCompleteBoundedEvidence(t *testing.T) {
	decision, err := EvaluateMigrationReadiness(completeMigrationEvidenceForTest())
	if err != nil {
		t.Fatal(err)
	}
	if !decision.EligibleForMigrationRehearsal || len(decision.MissingGates) != 0 {
		t.Fatalf("unexpected decision: %+v", decision)
	}
	if decision.ProductionCutoverAuthorized {
		t.Fatal("complete Beacon evidence unexpectedly authorized production cutover")
	}
}

func TestEvaluateMigrationReadinessRejectsCutoverClaim(t *testing.T) {
	evidence := completeMigrationEvidenceForTest()
	evidence.ProductionCutoverAuthorized = true
	if _, err := EvaluateMigrationReadiness(evidence); err == nil {
		t.Fatal("cutover-authorizing Beacon evidence unexpectedly accepted")
	}
}

func TestEvaluateMigrationReadinessRejectsInvalidArtifactIdentity(t *testing.T) {
	evidence := completeMigrationEvidenceForTest()
	evidence.RuntimeArtifactSHA256 = strings.Repeat("z", 64)
	if _, err := EvaluateMigrationReadiness(evidence); err == nil {
		t.Fatal("invalid Beacon runtime artifact digest unexpectedly accepted")
	}
}

func completeMigrationEvidenceForTest() MigrationEvidence {
	return MigrationEvidence{
		Schema:                             MigrationEvidenceSchemaV1,
		RecordedAt:                         time.Date(2026, 8, 29, 4, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
		SourceRevision:                     strings.Repeat("a", 40),
		RuntimeArtifactSHA256:              strings.Repeat("b", 64),
		ResolverParityValidated:            true,
		PrivateRecursionValidated:          true,
		DNSSECValidated:                    true,
		TrustAnchorRecoveryRehearsalPassed: true,
		RestartFailureValidated:            true,
		CacheBehaviorValidated:             true,
		EncryptedDNSValidated:              true,
		BackupRestoreProven:                true,
		RollbackRehearsed:                  true,
		ObservabilityValidated:             true,
		ManagerIntegrationValidated:        true,
		PrivacyShieldValidated:             true,
		WardveilSecurityValidated:          true,
		EverkeepValidated:                  true,
		GlazeUIStableValidated:             true,
		MeshCoordinationValidated:          true,
		IdentityIntegrationValidated:       true,
		GovernanceIntegrationValidated:     true,
		ProductionCutoverAuthorized:        false,
	}
}
