package gcdns

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const PolicyFilterListRecoveryBundleSchemaV1 = "goreecloud-beacon-filter-list-recovery-bundle/v1"

// PolicyFilterListRecoveryBundle binds the filter-list trusted-key recovery
// point and managed administrative configuration recovery point into one
// integrity-protected recovery generation. It contains no private signing
// material, acquisition credentials, list content, or runtime source objects.
type PolicyFilterListRecoveryBundle struct {
	Schema                 string                                          `json:"schema"`
	CreatedAt              string                                          `json:"created_at"`
	StateFingerprintSHA256 string                                          `json:"state_fingerprint_sha256"`
	TrustedKeys            PolicyFilterListTrustedKeyRecoveryPoint         `json:"trusted_keys"`
	ManagedConfig          PolicyFilterListManagedConfigRecoveryPoint      `json:"managed_config"`
}

// PolicyFilterListRecoveryBundleCandidate is a non-activating restore
// candidate. ManagedSources retain the currently accepted local runtime Source
// objects. A later, separately authorized activation path must persist and
// activate the candidate only after all required recovery gates succeed.
type PolicyFilterListRecoveryBundleCandidate struct {
	TrustedKeys           PolicyFilterListTrustedKeyState
	ManagedSources        []PolicyFilterListManagedSource
	ManagedConfigRevision uint64
}

type policyFilterListRecoveryBundleFingerprintState struct {
	CreatedAt     string                                     `json:"created_at"`
	TrustedKeys   PolicyFilterListTrustedKeyRecoveryPoint    `json:"trusted_keys"`
	ManagedConfig PolicyFilterListManagedConfigRecoveryPoint `json:"managed_config"`
}

// BuildPolicyFilterListRecoveryBundle creates one deterministic recovery set
// from independently valid trusted-key and managed-configuration recovery
// points. The resulting fingerprint binds both components and the bundle
// capture time so protected recovery evidence cannot silently mix components
// from another bundle.
func BuildPolicyFilterListRecoveryBundle(trustedKeys PolicyFilterListTrustedKeyRecoveryPoint, managedConfig PolicyFilterListManagedConfigRecoveryPoint, now time.Time) (PolicyFilterListRecoveryBundle, error) {
	if now.IsZero() {
		return PolicyFilterListRecoveryBundle{}, errors.New("goreecloud dns: filter-list recovery bundle time is required")
	}
	if err := validatePolicyFilterListTrustedKeyRecoveryPoint(trustedKeys); err != nil {
		return PolicyFilterListRecoveryBundle{}, fmt.Errorf("goreecloud dns: filter-list recovery bundle trusted keys: %w", err)
	}
	if err := validatePolicyFilterListManagedConfigRecoveryPoint(managedConfig); err != nil {
		return PolicyFilterListRecoveryBundle{}, fmt.Errorf("goreecloud dns: filter-list recovery bundle managed config: %w", err)
	}

	createdAt := now.UTC()
	if err := validatePolicyFilterListRecoveryBundleComponentTimes(createdAt, trustedKeys.CreatedAt, managedConfig.CreatedAt); err != nil {
		return PolicyFilterListRecoveryBundle{}, err
	}

	canonicalTrusted, err := canonicalPolicyFilterListTrustedKeyRecoveryPoint(trustedKeys)
	if err != nil {
		return PolicyFilterListRecoveryBundle{}, err
	}
	canonicalManaged, err := canonicalPolicyFilterListManagedConfigRecoveryPoint(managedConfig)
	if err != nil {
		return PolicyFilterListRecoveryBundle{}, err
	}

	bundle := PolicyFilterListRecoveryBundle{
		Schema:        PolicyFilterListRecoveryBundleSchemaV1,
		CreatedAt:     createdAt.Format(time.RFC3339Nano),
		TrustedKeys:   canonicalTrusted,
		ManagedConfig: canonicalManaged,
	}
	fingerprint, err := policyFilterListRecoveryBundleFingerprint(bundle)
	if err != nil {
		return PolicyFilterListRecoveryBundle{}, err
	}
	bundle.StateFingerprintSHA256 = fingerprint
	return bundle, nil
}

// StagePolicyFilterListRecoveryBundle validates independently retained bundle
// evidence, then stages both component candidates without mutating or persisting
// current state. The externally retained bundle fingerprint binds the component
// fingerprints, so the already-verified embedded component fingerprints can be
// used when invoking the existing component staging gates.
func StagePolicyFilterListRecoveryBundle(currentTrustedKeys PolicyFilterListTrustedKeyState, currentManager *PolicyFilterListManager, currentManagedConfigRevision uint64, recovery PolicyFilterListRecoveryBundle, expectedBundleFingerprint string) (PolicyFilterListRecoveryBundleCandidate, error) {
	if err := validatePolicyFilterListRecoveryBundle(recovery); err != nil {
		return PolicyFilterListRecoveryBundleCandidate{}, err
	}

	expected, err := normalizePolicyFilterListSHA256(expectedBundleFingerprint)
	if err != nil {
		return PolicyFilterListRecoveryBundleCandidate{}, fmt.Errorf("goreecloud dns: filter-list recovery bundle expected fingerprint: %w", err)
	}
	stored, err := normalizePolicyFilterListSHA256(recovery.StateFingerprintSHA256)
	if err != nil {
		return PolicyFilterListRecoveryBundleCandidate{}, fmt.Errorf("goreecloud dns: filter-list recovery bundle state fingerprint: %w", err)
	}
	if expected != stored {
		return PolicyFilterListRecoveryBundleCandidate{}, errors.New("goreecloud dns: filter-list recovery bundle evidence fingerprint mismatch")
	}

	trustedCandidate, err := StagePolicyFilterListTrustedKeyRecoveryPoint(
		currentTrustedKeys,
		recovery.TrustedKeys,
		recovery.TrustedKeys.StateFingerprintSHA256,
	)
	if err != nil {
		return PolicyFilterListRecoveryBundleCandidate{}, fmt.Errorf("goreecloud dns: filter-list recovery bundle trusted keys: %w", err)
	}
	managedCandidate, err := StagePolicyFilterListManagedConfigRecoveryPoint(
		currentManager,
		currentManagedConfigRevision,
		recovery.ManagedConfig,
		recovery.ManagedConfig.StateFingerprintSHA256,
	)
	if err != nil {
		return PolicyFilterListRecoveryBundleCandidate{}, fmt.Errorf("goreecloud dns: filter-list recovery bundle managed config: %w", err)
	}

	return PolicyFilterListRecoveryBundleCandidate{
		TrustedKeys:           trustedCandidate,
		ManagedSources:        managedCandidate,
		ManagedConfigRevision: recovery.ManagedConfig.Revision,
	}, nil
}

func validatePolicyFilterListRecoveryBundle(recovery PolicyFilterListRecoveryBundle) error {
	if recovery.Schema != PolicyFilterListRecoveryBundleSchemaV1 {
		return errors.New("goreecloud dns: unsupported filter-list recovery bundle schema")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, recovery.CreatedAt)
	if err != nil {
		return errors.New("goreecloud dns: filter-list recovery bundle created_at is invalid")
	}
	if err = validatePolicyFilterListTrustedKeyRecoveryPoint(recovery.TrustedKeys); err != nil {
		return fmt.Errorf("goreecloud dns: filter-list recovery bundle trusted keys: %w", err)
	}
	if err = validatePolicyFilterListManagedConfigRecoveryPoint(recovery.ManagedConfig); err != nil {
		return fmt.Errorf("goreecloud dns: filter-list recovery bundle managed config: %w", err)
	}
	if err = validatePolicyFilterListRecoveryBundleComponentTimes(createdAt, recovery.TrustedKeys.CreatedAt, recovery.ManagedConfig.CreatedAt); err != nil {
		return err
	}

	fingerprint, err := policyFilterListRecoveryBundleFingerprint(recovery)
	if err != nil {
		return err
	}
	stored, err := normalizePolicyFilterListSHA256(recovery.StateFingerprintSHA256)
	if err != nil {
		return fmt.Errorf("goreecloud dns: filter-list recovery bundle state fingerprint: %w", err)
	}
	if stored != fingerprint {
		return errors.New("goreecloud dns: filter-list recovery bundle state fingerprint mismatch")
	}
	return nil
}

func validatePolicyFilterListRecoveryBundleComponentTimes(bundleCreatedAt time.Time, trustedKeysCreatedAt, managedConfigCreatedAt string) error {
	trustedCreatedAt, err := time.Parse(time.RFC3339Nano, trustedKeysCreatedAt)
	if err != nil {
		return errors.New("goreecloud dns: filter-list recovery bundle trusted-key created_at is invalid")
	}
	managedCreatedAt, err := time.Parse(time.RFC3339Nano, managedConfigCreatedAt)
	if err != nil {
		return errors.New("goreecloud dns: filter-list recovery bundle managed-config created_at is invalid")
	}
	if trustedCreatedAt.After(bundleCreatedAt) || managedCreatedAt.After(bundleCreatedAt) {
		return errors.New("goreecloud dns: filter-list recovery bundle predates a protected component")
	}
	return nil
}

func canonicalPolicyFilterListTrustedKeyRecoveryPoint(recovery PolicyFilterListTrustedKeyRecoveryPoint) (PolicyFilterListTrustedKeyRecoveryPoint, error) {
	canonical := recovery
	canonical.State = canonicalPolicyFilterListTrustedKeyState(recovery.State)
	fingerprint, err := normalizePolicyFilterListSHA256(recovery.StateFingerprintSHA256)
	if err != nil {
		return PolicyFilterListTrustedKeyRecoveryPoint{}, fmt.Errorf("goreecloud dns: filter-list recovery bundle trusted-key fingerprint: %w", err)
	}
	canonical.StateFingerprintSHA256 = fingerprint
	return canonical, nil
}

func canonicalPolicyFilterListManagedConfigRecoveryPoint(recovery PolicyFilterListManagedConfigRecoveryPoint) (PolicyFilterListManagedConfigRecoveryPoint, error) {
	canonical := recovery
	canonical.Sources = canonicalPolicyFilterListManagedConfigRecoverySources(recovery.Sources)
	fingerprint, err := normalizePolicyFilterListSHA256(recovery.StateFingerprintSHA256)
	if err != nil {
		return PolicyFilterListManagedConfigRecoveryPoint{}, fmt.Errorf("goreecloud dns: filter-list recovery bundle managed-config fingerprint: %w", err)
	}
	canonical.StateFingerprintSHA256 = fingerprint
	return canonical, nil
}

func policyFilterListRecoveryBundleFingerprint(recovery PolicyFilterListRecoveryBundle) (string, error) {
	canonicalTrusted, err := canonicalPolicyFilterListTrustedKeyRecoveryPoint(recovery.TrustedKeys)
	if err != nil {
		return "", err
	}
	canonicalManaged, err := canonicalPolicyFilterListManagedConfigRecoveryPoint(recovery.ManagedConfig)
	if err != nil {
		return "", err
	}
	state := policyFilterListRecoveryBundleFingerprintState{
		CreatedAt:     recovery.CreatedAt,
		TrustedKeys:   canonicalTrusted,
		ManagedConfig: canonicalManaged,
	}
	data, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("goreecloud dns: encode filter-list recovery bundle state: %w", err)
	}
	digest := sha256.Sum256(data)
	return strings.ToLower(hex.EncodeToString(digest[:])), nil
}
