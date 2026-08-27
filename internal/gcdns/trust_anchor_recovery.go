package gcdns

import (
	"errors"
	"strings"
	"time"
)

const TrustAnchorRecoveryPointSchemaV1 = "goreecloud-beacon-trust-anchor-recovery/v1"

// TrustAnchorRecoveryPoint is an operator-controlled emergency recovery record
// captured before a pending trust-anchor set is activated. It is not an
// automatic rollback policy and must never bypass fresh DNSSEC rollover review.
type TrustAnchorRecoveryPoint struct {
	Schema             string              `json:"schema"`
	CreatedAt          string              `json:"created_at"`
	ActiveFingerprint  string              `json:"active_fingerprint"`
	PendingFingerprint string              `json:"pending_fingerprint"`
	Active             []TrustAnchorRecord `json:"active"`
}

func BuildTrustAnchorRecoveryPoint(state TrustAnchorState, now time.Time) (TrustAnchorRecoveryPoint, error) {
	if err := validateTrustAnchorState(state); err != nil {
		return TrustAnchorRecoveryPoint{}, err
	}
	if state.Pending == nil {
		return TrustAnchorRecoveryPoint{}, errors.New("goreecloud dns: trust-anchor recovery point requires a pending update")
	}
	if now.IsZero() {
		return TrustAnchorRecoveryPoint{}, errors.New("goreecloud dns: trust-anchor recovery point time is required")
	}
	activeFingerprint, err := trustAnchorFingerprint(state.Active)
	if err != nil {
		return TrustAnchorRecoveryPoint{}, err
	}
	return TrustAnchorRecoveryPoint{
		Schema:             TrustAnchorRecoveryPointSchemaV1,
		CreatedAt:          now.UTC().Format(time.RFC3339Nano),
		ActiveFingerprint:  activeFingerprint,
		PendingFingerprint: state.Pending.Fingerprint,
		Active:             append([]TrustAnchorRecord(nil), state.Active...),
	}, nil
}

// RestoreTrustAnchorRecoveryPoint applies an explicit emergency rollback only
// when the currently active set exactly matches the candidate that followed the
// recovery point. It never runs automatically and never restores over a newer
// pending transition.
func RestoreTrustAnchorRecoveryPoint(store *TrustAnchorStore, state TrustAnchorState, recovery TrustAnchorRecoveryPoint, expectedCurrentFingerprint string) (TrustAnchorState, error) {
	if store == nil {
		return TrustAnchorState{}, errors.New("goreecloud dns: trust-anchor store is required")
	}
	if err := validateTrustAnchorState(state); err != nil {
		return TrustAnchorState{}, err
	}
	if state.Pending != nil {
		return TrustAnchorState{}, errors.New("goreecloud dns: trust-anchor recovery cannot run while an update is pending")
	}
	if err := validateTrustAnchorRecoveryPoint(recovery); err != nil {
		return TrustAnchorState{}, err
	}
	currentFingerprint, err := trustAnchorFingerprint(state.Active)
	if err != nil {
		return TrustAnchorState{}, err
	}
	expectedCurrentFingerprint = strings.ToLower(strings.TrimSpace(expectedCurrentFingerprint))
	if expectedCurrentFingerprint == "" || expectedCurrentFingerprint != currentFingerprint {
		return TrustAnchorState{}, errors.New("goreecloud dns: trust-anchor recovery current fingerprint mismatch")
	}
	if currentFingerprint != recovery.PendingFingerprint {
		return TrustAnchorState{}, errors.New("goreecloud dns: trust-anchor recovery point does not match current activated set")
	}

	next := state
	next.Active = append([]TrustAnchorRecord(nil), recovery.Active...)
	next.Pending = nil
	next.UpdatedAt = store.now().UTC().Format(time.RFC3339Nano)
	if err := validateTrustAnchorState(next); err != nil {
		return TrustAnchorState{}, err
	}
	return next, nil
}

func validateTrustAnchorRecoveryPoint(recovery TrustAnchorRecoveryPoint) error {
	if recovery.Schema != TrustAnchorRecoveryPointSchemaV1 {
		return errors.New("goreecloud dns: unsupported trust-anchor recovery point schema")
	}
	if _, err := time.Parse(time.RFC3339Nano, recovery.CreatedAt); err != nil {
		return errors.New("goreecloud dns: trust-anchor recovery point created_at is invalid")
	}
	if err := validateTrustAnchorRecords(recovery.Active); err != nil {
		return err
	}
	activeFingerprint, err := trustAnchorFingerprint(recovery.Active)
	if err != nil {
		return err
	}
	if strings.ToLower(strings.TrimSpace(recovery.ActiveFingerprint)) != activeFingerprint {
		return errors.New("goreecloud dns: trust-anchor recovery active fingerprint mismatch")
	}
	pendingFingerprint := strings.ToLower(strings.TrimSpace(recovery.PendingFingerprint))
	if pendingFingerprint == "" || pendingFingerprint == activeFingerprint {
		return errors.New("goreecloud dns: trust-anchor recovery pending fingerprint is invalid")
	}
	return nil
}
