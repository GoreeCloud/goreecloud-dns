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

const PolicyFilterListManagedConfigRecoveryPointSchemaV1 = "goreecloud-beacon-filter-list-managed-config-recovery/v1"

// PolicyFilterListManagedConfigRecoverySource is the durable administrative
// portion of a managed filter-list binding. Runtime snapshot-source objects are
// intentionally excluded from recovery evidence and are supplied only by the
// already-accepted local runtime during staging.
type PolicyFilterListManagedConfigRecoverySource struct {
	ID               string          `json:"id"`
	ExpectedSourceID string          `json:"expected_source_id"`
	Enabled          bool            `json:"enabled"`
	Required         bool            `json:"required"`
	Priority         int             `json:"priority"`
	Schedule         *PolicySchedule `json:"schedule,omitempty"`
	BlockRcode       int             `json:"block_rcode"`
}

// PolicyFilterListManagedConfigRecoveryPoint is a deterministic, revisioned,
// integrity-bound recovery record for managed filter-list configuration. It is
// non-activating and contains no list content, acquisition credentials, signing
// keys, or runtime source objects.
type PolicyFilterListManagedConfigRecoveryPoint struct {
	Schema                 string                                        `json:"schema"`
	CreatedAt              string                                        `json:"created_at"`
	Revision               uint64                                        `json:"revision"`
	StateFingerprintSHA256 string                                        `json:"state_fingerprint_sha256"`
	Sources                []PolicyFilterListManagedConfigRecoverySource `json:"sources"`
}

type policyFilterListManagedConfigFingerprintState struct {
	Revision uint64                                        `json:"revision"`
	Sources  []PolicyFilterListManagedConfigRecoverySource `json:"sources"`
}

// BuildPolicyFilterListManagedConfigRecoveryPoint captures only the reviewed
// administrative configuration from an existing manager. The returned point is
// suitable for protection by Everkeep or another approved recovery authority.
func BuildPolicyFilterListManagedConfigRecoveryPoint(manager *PolicyFilterListManager, revision uint64, now time.Time) (PolicyFilterListManagedConfigRecoveryPoint, error) {
	if manager == nil {
		return PolicyFilterListManagedConfigRecoveryPoint{}, errors.New("goreecloud dns: managed filter-list recovery manager is required")
	}
	if revision == 0 {
		return PolicyFilterListManagedConfigRecoveryPoint{}, errors.New("goreecloud dns: managed filter-list recovery revision must be greater than zero")
	}
	if now.IsZero() {
		return PolicyFilterListManagedConfigRecoveryPoint{}, errors.New("goreecloud dns: managed filter-list recovery point time is required")
	}

	sources := managedConfigRecoverySources(manager.snapshotSources())
	if err := validatePolicyFilterListManagedConfigRecoverySources(sources); err != nil {
		return PolicyFilterListManagedConfigRecoveryPoint{}, err
	}
	fingerprint, err := policyFilterListManagedConfigRecoveryFingerprint(revision, sources)
	if err != nil {
		return PolicyFilterListManagedConfigRecoveryPoint{}, err
	}

	return PolicyFilterListManagedConfigRecoveryPoint{
		Schema:                 PolicyFilterListManagedConfigRecoveryPointSchemaV1,
		CreatedAt:              now.UTC().Format(time.RFC3339Nano),
		Revision:               revision,
		StateFingerprintSHA256: fingerprint,
		Sources:                sources,
	}, nil
}

// StagePolicyFilterListManagedConfigRecoveryPoint validates protected recovery
// evidence and returns a candidate manager configuration only. It does not
// mutate current, save configuration, refresh a list, start a scheduler, change
// resolver policy, or activate production state. Runtime Source objects are
// preserved from the current locally accepted bindings.
func StagePolicyFilterListManagedConfigRecoveryPoint(current *PolicyFilterListManager, currentRevision uint64, recovery PolicyFilterListManagedConfigRecoveryPoint, expectedStateFingerprint string) ([]PolicyFilterListManagedSource, error) {
	if current == nil {
		return nil, errors.New("goreecloud dns: current managed filter-list manager is required")
	}
	if currentRevision == 0 {
		return nil, errors.New("goreecloud dns: current managed filter-list revision must be greater than zero")
	}
	if err := validatePolicyFilterListManagedConfigRecoveryPoint(recovery); err != nil {
		return nil, err
	}
	if recovery.Revision < currentRevision {
		return nil, errors.New("goreecloud dns: managed filter-list recovery revision is older than current configuration")
	}

	expected, err := normalizePolicyFilterListSHA256(expectedStateFingerprint)
	if err != nil {
		return nil, fmt.Errorf("goreecloud dns: managed filter-list recovery expected fingerprint: %w", err)
	}
	stored, err := normalizePolicyFilterListSHA256(recovery.StateFingerprintSHA256)
	if err != nil {
		return nil, fmt.Errorf("goreecloud dns: managed filter-list recovery state fingerprint: %w", err)
	}
	if expected != stored {
		return nil, errors.New("goreecloud dns: managed filter-list recovery evidence fingerprint mismatch")
	}

	currentSources := current.snapshotSources()
	currentByID := make(map[string]PolicyFilterListManagedSource, len(currentSources))
	for _, source := range currentSources {
		currentByID[source.ID] = source
	}
	if len(currentByID) != len(recovery.Sources) {
		return nil, errors.New("goreecloud dns: managed filter-list recovery changes the accepted source set")
	}

	candidate := make([]PolicyFilterListManagedSource, 0, len(recovery.Sources))
	for _, recovered := range recovery.Sources {
		local, ok := currentByID[recovered.ID]
		if !ok {
			return nil, fmt.Errorf("goreecloud dns: managed filter-list recovery introduces unknown source %q", recovered.ID)
		}
		if local.ExpectedSourceID != recovered.ExpectedSourceID {
			return nil, fmt.Errorf("goreecloud dns: managed filter-list recovery rebinds source identity for %q", recovered.ID)
		}
		if local.Required != recovered.Required {
			return nil, fmt.Errorf("goreecloud dns: managed filter-list recovery rewrites required-source authority for %q", recovered.ID)
		}
		candidate = append(candidate, PolicyFilterListManagedSource{
			ID:               local.ID,
			ExpectedSourceID: local.ExpectedSourceID,
			Enabled:          recovered.Enabled,
			Required:         local.Required,
			Priority:         recovered.Priority,
			Schedule:         clonePolicySchedule(recovered.Schedule),
			BlockRcode:       recovered.BlockRcode,
			Source:           local.Source,
		})
	}

	validated, err := NewPolicyFilterListManager(candidate)
	if err != nil {
		return nil, fmt.Errorf("goreecloud dns: managed filter-list recovery candidate: %w", err)
	}
	return validated.snapshotSources(), nil
}

func validatePolicyFilterListManagedConfigRecoveryPoint(recovery PolicyFilterListManagedConfigRecoveryPoint) error {
	if recovery.Schema != PolicyFilterListManagedConfigRecoveryPointSchemaV1 {
		return errors.New("goreecloud dns: unsupported managed filter-list recovery point schema")
	}
	if _, err := time.Parse(time.RFC3339Nano, recovery.CreatedAt); err != nil {
		return errors.New("goreecloud dns: managed filter-list recovery point created_at is invalid")
	}
	if recovery.Revision == 0 {
		return errors.New("goreecloud dns: managed filter-list recovery revision must be greater than zero")
	}
	if err := validatePolicyFilterListManagedConfigRecoverySources(recovery.Sources); err != nil {
		return err
	}
	fingerprint, err := policyFilterListManagedConfigRecoveryFingerprint(recovery.Revision, recovery.Sources)
	if err != nil {
		return err
	}
	stored, err := normalizePolicyFilterListSHA256(recovery.StateFingerprintSHA256)
	if err != nil {
		return fmt.Errorf("goreecloud dns: managed filter-list recovery state fingerprint: %w", err)
	}
	if stored != fingerprint {
		return errors.New("goreecloud dns: managed filter-list recovery state fingerprint mismatch")
	}
	return nil
}

func validatePolicyFilterListManagedConfigRecoverySources(sources []PolicyFilterListManagedConfigRecoverySource) error {
	if len(sources) == 0 {
		return errors.New("goreecloud dns: managed filter-list recovery requires at least one source")
	}
	seenIDs := make(map[string]struct{}, len(sources))
	seenSourceIDs := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		id := strings.TrimSpace(source.ID)
		expectedSourceID := strings.TrimSpace(source.ExpectedSourceID)
		if id == "" || id != source.ID {
			return errors.New("goreecloud dns: managed filter-list recovery source ID must be canonical and non-empty")
		}
		if expectedSourceID == "" || expectedSourceID != source.ExpectedSourceID {
			return fmt.Errorf("goreecloud dns: managed filter-list recovery source identity for %q must be canonical and non-empty", id)
		}
		if _, exists := seenIDs[id]; exists {
			return fmt.Errorf("goreecloud dns: duplicate managed filter-list recovery source %q", id)
		}
		seenIDs[id] = struct{}{}
		if _, exists := seenSourceIDs[expectedSourceID]; exists {
			return fmt.Errorf("goreecloud dns: duplicate managed filter-list recovery source identity %q", expectedSourceID)
		}
		seenSourceIDs[expectedSourceID] = struct{}{}
		if source.Required && !source.Enabled {
			return fmt.Errorf("goreecloud dns: required managed filter-list recovery source %q cannot be disabled", id)
		}
	}
	return nil
}

func managedConfigRecoverySources(sources []PolicyFilterListManagedSource) []PolicyFilterListManagedConfigRecoverySource {
	out := make([]PolicyFilterListManagedConfigRecoverySource, 0, len(sources))
	for _, source := range sources {
		out = append(out, PolicyFilterListManagedConfigRecoverySource{
			ID:               source.ID,
			ExpectedSourceID: source.ExpectedSourceID,
			Enabled:          source.Enabled,
			Required:         source.Required,
			Priority:         source.Priority,
			Schedule:         clonePolicySchedule(source.Schedule),
			BlockRcode:       source.BlockRcode,
		})
	}
	return canonicalPolicyFilterListManagedConfigRecoverySources(out)
}

func canonicalPolicyFilterListManagedConfigRecoverySources(sources []PolicyFilterListManagedConfigRecoverySource) []PolicyFilterListManagedConfigRecoverySource {
	out := make([]PolicyFilterListManagedConfigRecoverySource, len(sources))
	for i, source := range sources {
		out[i] = source
		out[i].Schedule = clonePolicySchedule(source.Schedule)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func policyFilterListManagedConfigRecoveryFingerprint(revision uint64, sources []PolicyFilterListManagedConfigRecoverySource) (string, error) {
	canonical := canonicalPolicyFilterListManagedConfigRecoverySources(sources)
	if err := validatePolicyFilterListManagedConfigRecoverySources(canonical); err != nil {
		return "", err
	}
	data, err := json.Marshal(policyFilterListManagedConfigFingerprintState{Revision: revision, Sources: canonical})
	if err != nil {
		return "", fmt.Errorf("goreecloud dns: encode managed filter-list recovery state: %w", err)
	}
	digest := sha256.Sum256(data)
	return strings.ToLower(hex.EncodeToString(digest[:])), nil
}
