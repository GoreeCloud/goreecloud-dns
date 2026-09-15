package gcdns

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const maxPolicyFilterListRecoveryBundleBytes = 1 << 20

// EncodePolicyFilterListRecoveryBundle serializes one already integrity-bound
// recovery bundle into deterministic, human-reviewable JSON suitable for an
// approved recovery authority. Encoding does not persist or activate state.
func EncodePolicyFilterListRecoveryBundle(recovery PolicyFilterListRecoveryBundle) ([]byte, error) {
	if err := validatePolicyFilterListRecoveryBundle(recovery); err != nil {
		return nil, err
	}
	canonical, err := canonicalPolicyFilterListRecoveryBundle(recovery)
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(canonical, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("goreecloud dns: encode filter-list recovery bundle: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxPolicyFilterListRecoveryBundleBytes {
		return nil, fmt.Errorf("goreecloud dns: filter-list recovery bundle exceeds %d bytes", maxPolicyFilterListRecoveryBundleBytes)
	}
	return data, nil
}

// DecodePolicyFilterListRecoveryBundle parses one bounded recovery artifact.
// Unknown fields and trailing JSON fail closed. The returned bundle is
// canonicalized but remains non-activating; callers must still stage it against
// independently retained recovery evidence before any later authorized restore.
func DecodePolicyFilterListRecoveryBundle(data []byte) (PolicyFilterListRecoveryBundle, error) {
	if len(data) == 0 {
		return PolicyFilterListRecoveryBundle{}, errors.New("goreecloud dns: filter-list recovery bundle data is required")
	}
	if len(data) > maxPolicyFilterListRecoveryBundleBytes {
		return PolicyFilterListRecoveryBundle{}, fmt.Errorf("goreecloud dns: filter-list recovery bundle exceeds %d bytes", maxPolicyFilterListRecoveryBundleBytes)
	}

	var recovery PolicyFilterListRecoveryBundle
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&recovery); err != nil {
		return PolicyFilterListRecoveryBundle{}, fmt.Errorf("goreecloud dns: decode filter-list recovery bundle: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return PolicyFilterListRecoveryBundle{}, fmt.Errorf("goreecloud dns: decode trailing filter-list recovery bundle: %w", err)
		}
		return PolicyFilterListRecoveryBundle{}, errors.New("goreecloud dns: filter-list recovery bundle contains trailing JSON data")
	}
	if err := validatePolicyFilterListRecoveryBundle(recovery); err != nil {
		return PolicyFilterListRecoveryBundle{}, err
	}
	return canonicalPolicyFilterListRecoveryBundle(recovery)
}

func canonicalPolicyFilterListRecoveryBundle(recovery PolicyFilterListRecoveryBundle) (PolicyFilterListRecoveryBundle, error) {
	canonical := recovery
	trusted, err := canonicalPolicyFilterListTrustedKeyRecoveryPoint(recovery.TrustedKeys)
	if err != nil {
		return PolicyFilterListRecoveryBundle{}, err
	}
	managed, err := canonicalPolicyFilterListManagedConfigRecoveryPoint(recovery.ManagedConfig)
	if err != nil {
		return PolicyFilterListRecoveryBundle{}, err
	}
	fingerprint, err := normalizePolicyFilterListSHA256(recovery.StateFingerprintSHA256)
	if err != nil {
		return PolicyFilterListRecoveryBundle{}, fmt.Errorf("goreecloud dns: filter-list recovery bundle state fingerprint: %w", err)
	}
	canonical.TrustedKeys = trusted
	canonical.ManagedConfig = managed
	canonical.StateFingerprintSHA256 = fingerprint
	return canonical, nil
}
