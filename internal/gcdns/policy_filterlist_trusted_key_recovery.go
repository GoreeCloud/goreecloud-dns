package gcdns

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const PolicyFilterListTrustedKeyRecoveryPointSchemaV1 = "goreecloud-beacon-filter-list-trusted-key-recovery/v1"

// PolicyFilterListTrustedKeyRecoveryPoint is a deterministic, integrity-bound
// backup record for Beacon filter-list public-key rotation and revocation state.
// It contains no private signing material and does not activate restored state.
type PolicyFilterListTrustedKeyRecoveryPoint struct {
	Schema                 string                          `json:"schema"`
	CreatedAt              string                          `json:"created_at"`
	StateFingerprintSHA256 string                          `json:"state_fingerprint_sha256"`
	State                  PolicyFilterListTrustedKeyState `json:"state"`
}

// BuildPolicyFilterListTrustedKeyRecoveryPoint creates a canonical recovery
// record suitable for protection by Everkeep or another approved recovery
// authority. Key ordering is normalized before the state fingerprint is built.
func BuildPolicyFilterListTrustedKeyRecoveryPoint(state PolicyFilterListTrustedKeyState, now time.Time) (PolicyFilterListTrustedKeyRecoveryPoint, error) {
	if err := validatePolicyFilterListTrustedKeyState(state); err != nil {
		return PolicyFilterListTrustedKeyRecoveryPoint{}, err
	}
	if now.IsZero() {
		return PolicyFilterListTrustedKeyRecoveryPoint{}, errors.New("goreecloud dns: filter-list trusted-key recovery point time is required")
	}

	canonical := canonicalPolicyFilterListTrustedKeyState(state)
	fingerprint, err := policyFilterListTrustedKeyStateFingerprint(canonical)
	if err != nil {
		return PolicyFilterListTrustedKeyRecoveryPoint{}, err
	}
	return PolicyFilterListTrustedKeyRecoveryPoint{
		Schema:                 PolicyFilterListTrustedKeyRecoveryPointSchemaV1,
		CreatedAt:              now.UTC().Format(time.RFC3339Nano),
		StateFingerprintSHA256: fingerprint,
		State:                  canonical,
	}, nil
}

// StagePolicyFilterListTrustedKeyRecoveryPoint validates a protected recovery
// point and returns a restore candidate only. It never writes the trusted-key
// store or changes a live verification key set. expectedStateFingerprint must
// come from independently retained recovery evidence (for example Everkeep).
func StagePolicyFilterListTrustedKeyRecoveryPoint(current PolicyFilterListTrustedKeyState, recovery PolicyFilterListTrustedKeyRecoveryPoint, expectedStateFingerprint string) (PolicyFilterListTrustedKeyState, error) {
	if err := validatePolicyFilterListTrustedKeyState(current); err != nil {
		return PolicyFilterListTrustedKeyState{}, err
	}
	if err := validatePolicyFilterListTrustedKeyRecoveryPoint(recovery); err != nil {
		return PolicyFilterListTrustedKeyState{}, err
	}

	expected, err := normalizePolicyFilterListSHA256(expectedStateFingerprint)
	if err != nil {
		return PolicyFilterListTrustedKeyState{}, fmt.Errorf("goreecloud dns: filter-list trusted-key recovery expected fingerprint: %w", err)
	}
	recoveryFingerprint, err := normalizePolicyFilterListSHA256(recovery.StateFingerprintSHA256)
	if err != nil {
		return PolicyFilterListTrustedKeyState{}, fmt.Errorf("goreecloud dns: filter-list trusted-key recovery state fingerprint: %w", err)
	}
	if expected != recoveryFingerprint {
		return PolicyFilterListTrustedKeyState{}, errors.New("goreecloud dns: filter-list trusted-key recovery evidence fingerprint mismatch")
	}
	if err := validatePolicyFilterListTrustedKeyRecoverySupersedes(current, recovery.State); err != nil {
		return PolicyFilterListTrustedKeyState{}, err
	}
	return canonicalPolicyFilterListTrustedKeyState(recovery.State), nil
}

func validatePolicyFilterListTrustedKeyRecoveryPoint(recovery PolicyFilterListTrustedKeyRecoveryPoint) error {
	if recovery.Schema != PolicyFilterListTrustedKeyRecoveryPointSchemaV1 {
		return errors.New("goreecloud dns: unsupported filter-list trusted-key recovery point schema")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, recovery.CreatedAt)
	if err != nil {
		return errors.New("goreecloud dns: filter-list trusted-key recovery point created_at is invalid")
	}
	if err := validatePolicyFilterListTrustedKeyState(recovery.State); err != nil {
		return err
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, recovery.State.UpdatedAt)
	if err != nil {
		return errors.New("goreecloud dns: filter-list trusted-key recovery state updated_at is invalid")
	}
	if updatedAt.After(createdAt) {
		return errors.New("goreecloud dns: filter-list trusted-key recovery point predates protected state")
	}

	fingerprint, err := policyFilterListTrustedKeyStateFingerprint(recovery.State)
	if err != nil {
		return err
	}
	stored, err := normalizePolicyFilterListSHA256(recovery.StateFingerprintSHA256)
	if err != nil {
		return fmt.Errorf("goreecloud dns: filter-list trusted-key recovery state fingerprint: %w", err)
	}
	if stored != fingerprint {
		return errors.New("goreecloud dns: filter-list trusted-key recovery state fingerprint mismatch")
	}
	return nil
}

func validatePolicyFilterListTrustedKeyRecoverySupersedes(current, candidate PolicyFilterListTrustedKeyState) error {
	currentUpdatedAt, err := time.Parse(time.RFC3339Nano, current.UpdatedAt)
	if err != nil {
		return errors.New("goreecloud dns: current filter-list trusted-key state updated_at is invalid")
	}
	candidateUpdatedAt, err := time.Parse(time.RFC3339Nano, candidate.UpdatedAt)
	if err != nil {
		return errors.New("goreecloud dns: recovered filter-list trusted-key state updated_at is invalid")
	}
	if candidateUpdatedAt.Before(currentUpdatedAt) {
		return errors.New("goreecloud dns: filter-list trusted-key recovery state is older than current state")
	}

	candidateByID := make(map[string]PolicyFilterListTrustedKeyRecord, len(candidate.Keys))
	for _, record := range candidate.Keys {
		candidateByID[record.KeyID] = record
	}

	for _, existing := range current.Keys {
		recovered, ok := candidateByID[existing.KeyID]
		if !ok {
			return fmt.Errorf("goreecloud dns: filter-list trusted-key recovery drops existing key %q", existing.KeyID)
		}
		if existing.PublicKey != recovered.PublicKey ||
			existing.FingerprintSHA256 != recovered.FingerprintSHA256 ||
			existing.AddedAt != recovered.AddedAt ||
			existing.Source != recovered.Source {
			return fmt.Errorf("goreecloud dns: filter-list trusted-key recovery rewrites existing key %q", existing.KeyID)
		}
		if existing.RevokedAt != "" {
			if recovered.RevokedAt != existing.RevokedAt || recovered.RevocationReason != existing.RevocationReason {
				return fmt.Errorf("goreecloud dns: filter-list trusted-key recovery rewrites revocation for key %q", existing.KeyID)
			}
		}
	}
	return nil
}

func canonicalPolicyFilterListTrustedKeyState(state PolicyFilterListTrustedKeyState) PolicyFilterListTrustedKeyState {
	canonical := state
	canonical.Keys = append([]PolicyFilterListTrustedKeyRecord(nil), state.Keys...)
	sort.Slice(canonical.Keys, func(i, j int) bool { return canonical.Keys[i].KeyID < canonical.Keys[j].KeyID })
	return canonical
}

func policyFilterListTrustedKeyStateFingerprint(state PolicyFilterListTrustedKeyState) (string, error) {
	if err := validatePolicyFilterListTrustedKeyState(state); err != nil {
		return "", err
	}
	canonical := canonicalPolicyFilterListTrustedKeyState(state)
	data, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("goreecloud dns: encode filter-list trusted-key recovery state: %w", err)
	}
	digest := sha256.Sum256(data)
	return strings.ToLower(hex.EncodeToString(digest[:])), nil
}
