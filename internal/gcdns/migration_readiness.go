package gcdns

import (
	"errors"
	"strings"
	"time"
)

const MigrationEvidenceSchemaV1 = "goreecloud-beacon-migration-evidence/v1"

// MigrationEvidence records bounded acceptance state for one exact Beacon
// source revision and immutable runtime artifact. It intentionally contains no
// DNS queries, client identifiers, domain names, trust-anchor material,
// credentials, policy contents, private zones, or raw diagnostics.
type MigrationEvidence struct {
	Schema                             string `json:"schema"`
	RecordedAt                         string `json:"recorded_at"`
	SourceRevision                     string `json:"source_revision"`
	RuntimeArtifactSHA256              string `json:"runtime_artifact_sha256"`
	ResolverParityValidated            bool   `json:"resolver_parity_validated"`
	PrivateRecursionValidated          bool   `json:"private_recursion_validated"`
	DNSSECValidated                    bool   `json:"dnssec_validated"`
	TrustAnchorRecoveryRehearsalPassed bool   `json:"trust_anchor_recovery_rehearsal_passed"`
	RestartFailureValidated            bool   `json:"restart_failure_validated"`
	CacheBehaviorValidated             bool   `json:"cache_behavior_validated"`
	EncryptedDNSValidated              bool   `json:"encrypted_dns_validated"`
	BackupRestoreProven                bool   `json:"backup_restore_proven"`
	RollbackRehearsed                  bool   `json:"rollback_rehearsed"`
	ObservabilityValidated             bool   `json:"observability_validated"`
	ManagerIntegrationValidated        bool   `json:"manager_integration_validated"`
	PrivacyShieldValidated             bool   `json:"privacy_shield_validated"`
	WardveilSecurityValidated          bool   `json:"wardveil_security_validated"`
	EverkeepValidated                  bool   `json:"everkeep_validated"`
	GlazeUIStableValidated             bool   `json:"glaze_ui_stable_validated"`
	MeshCoordinationValidated          bool   `json:"mesh_coordination_validated"`
	IdentityIntegrationValidated       bool   `json:"identity_integration_validated"`
	GovernanceIntegrationValidated     bool   `json:"governance_integration_validated"`
	ProductionCutoverAuthorized        bool   `json:"production_cutover_authorized"`
}

// MigrationDecision reports whether Beacon has complete evidence for an
// explicitly approved migration rehearsal. It cannot transfer production DNS
// authority and always keeps production cutover authorization false.
type MigrationDecision struct {
	EligibleForMigrationRehearsal bool     `json:"eligible_for_migration_rehearsal"`
	MissingGates                  []string `json:"missing_gates,omitempty"`
	ProductionCutoverAuthorized   bool     `json:"production_cutover_authorized"`
}

func EvaluateMigrationReadiness(evidence MigrationEvidence) (MigrationDecision, error) {
	decision := MigrationDecision{ProductionCutoverAuthorized: false}
	if evidence.Schema != MigrationEvidenceSchemaV1 {
		return decision, errors.New("goreecloud dns: unsupported migration evidence schema")
	}
	if _, err := time.Parse(time.RFC3339Nano, evidence.RecordedAt); err != nil {
		return decision, errors.New("goreecloud dns: migration evidence recorded_at is invalid")
	}
	if !validMigrationHexIdentity(evidence.SourceRevision, 40, 64) {
		return decision, errors.New("goreecloud dns: migration evidence source revision is invalid")
	}
	if !validMigrationHexIdentity(evidence.RuntimeArtifactSHA256, 64) {
		return decision, errors.New("goreecloud dns: migration evidence runtime artifact digest is invalid")
	}
	if evidence.ProductionCutoverAuthorized {
		return decision, errors.New("goreecloud dns: migration evidence cannot authorize production cutover")
	}

	gates := []struct {
		name string
		pass bool
	}{
		{"resolver_parity_validated", evidence.ResolverParityValidated},
		{"private_recursion_validated", evidence.PrivateRecursionValidated},
		{"dnssec_validated", evidence.DNSSECValidated},
		{"trust_anchor_recovery_rehearsal_passed", evidence.TrustAnchorRecoveryRehearsalPassed},
		{"restart_failure_validated", evidence.RestartFailureValidated},
		{"cache_behavior_validated", evidence.CacheBehaviorValidated},
		{"encrypted_dns_validated", evidence.EncryptedDNSValidated},
		{"backup_restore_proven", evidence.BackupRestoreProven},
		{"rollback_rehearsed", evidence.RollbackRehearsed},
		{"observability_validated", evidence.ObservabilityValidated},
		{"manager_integration_validated", evidence.ManagerIntegrationValidated},
		{"privacy_shield_validated", evidence.PrivacyShieldValidated},
		{"wardveil_security_validated", evidence.WardveilSecurityValidated},
		{"everkeep_validated", evidence.EverkeepValidated},
		{"glaze_ui_stable_validated", evidence.GlazeUIStableValidated},
		{"mesh_coordination_validated", evidence.MeshCoordinationValidated},
		{"identity_integration_validated", evidence.IdentityIntegrationValidated},
		{"governance_integration_validated", evidence.GovernanceIntegrationValidated},
	}
	for _, gate := range gates {
		if !gate.pass {
			decision.MissingGates = append(decision.MissingGates, gate.name)
		}
	}
	decision.EligibleForMigrationRehearsal = len(decision.MissingGates) == 0
	return decision, nil
}

func validMigrationHexIdentity(value string, lengths ...int) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	for _, length := range lengths {
		if len(value) == length {
			return true
		}
	}
	return false
}
