package gcdns

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const trustAnchorRolloverSchema = "goreecloud-beacon-trust-anchor-rollover/v1"

type TrustAnchorRolloverState struct {
	Schema        string `json:"schema"`
	Fingerprint   string `json:"fingerprint"`
	FirstSeenAt   string `json:"first_seen_at"`
	LastSeenAt    string `json:"last_seen_at"`
	HoldDownUntil string `json:"hold_down_until"`
}

// NewTrustAnchorRolloverState begins a restart-serializable observation window
// for an already authenticated candidate root trust-anchor set. This state is
// timing evidence only and never activates the candidate.
func NewTrustAnchorRolloverState(anchors []*dns.DS, observedAt time.Time, holdDown time.Duration) (TrustAnchorRolloverState, error) {
	if observedAt.IsZero() {
		return TrustAnchorRolloverState{}, errors.New("goreecloud dns: rollover observation time is required")
	}
	if holdDown <= 0 {
		return TrustAnchorRolloverState{}, errors.New("goreecloud dns: rollover hold-down duration must be positive")
	}
	records := trustAnchorRecordsFromDS(anchors)
	fingerprint, err := trustAnchorFingerprint(records)
	if err != nil {
		return TrustAnchorRolloverState{}, err
	}
	now := observedAt.UTC()
	state := TrustAnchorRolloverState{
		Schema:        trustAnchorRolloverSchema,
		Fingerprint:   fingerprint,
		FirstSeenAt:   now.Format(time.RFC3339Nano),
		LastSeenAt:    now.Format(time.RFC3339Nano),
		HoldDownUntil: now.Add(holdDown).Format(time.RFC3339Nano),
	}
	return state, validateTrustAnchorRolloverState(state)
}

// ObserveTrustAnchorCandidate advances the last-seen timestamp only when the
// complete candidate set is unchanged and wall-clock time has not moved
// backwards relative to persisted state.
func ObserveTrustAnchorCandidate(state TrustAnchorRolloverState, anchors []*dns.DS, observedAt time.Time) (TrustAnchorRolloverState, error) {
	if err := validateTrustAnchorRolloverState(state); err != nil {
		return TrustAnchorRolloverState{}, err
	}
	if observedAt.IsZero() {
		return TrustAnchorRolloverState{}, errors.New("goreecloud dns: rollover observation time is required")
	}
	fingerprint, err := trustAnchorFingerprint(trustAnchorRecordsFromDS(anchors))
	if err != nil {
		return TrustAnchorRolloverState{}, err
	}
	if fingerprint != state.Fingerprint {
		return TrustAnchorRolloverState{}, errors.New("goreecloud dns: rollover candidate changed during hold-down")
	}
	lastSeen, _ := time.Parse(time.RFC3339Nano, state.LastSeenAt)
	now := observedAt.UTC()
	if now.Before(lastSeen) {
		return TrustAnchorRolloverState{}, errors.New("goreecloud dns: clock moved backwards during trust-anchor hold-down")
	}
	state.LastSeenAt = now.Format(time.RFC3339Nano)
	return state, nil
}

// TrustAnchorCandidateHoldDownComplete reports timing eligibility only. A true
// result does not approve, activate, or persist a new trust-anchor set.
func TrustAnchorCandidateHoldDownComplete(state TrustAnchorRolloverState, now time.Time) (bool, error) {
	if err := validateTrustAnchorRolloverState(state); err != nil {
		return false, err
	}
	if now.IsZero() {
		return false, errors.New("goreecloud dns: rollover evaluation time is required")
	}
	lastSeen, _ := time.Parse(time.RFC3339Nano, state.LastSeenAt)
	current := now.UTC()
	if current.Before(lastSeen) {
		return false, errors.New("goreecloud dns: clock moved backwards during trust-anchor hold-down")
	}
	holdDownUntil, _ := time.Parse(time.RFC3339Nano, state.HoldDownUntil)
	return !current.Before(holdDownUntil), nil
}

func validateTrustAnchorRolloverState(state TrustAnchorRolloverState) error {
	if state.Schema != trustAnchorRolloverSchema {
		return fmt.Errorf("goreecloud dns: unsupported trust-anchor rollover schema %q", state.Schema)
	}
	if len(strings.TrimSpace(state.Fingerprint)) != 64 {
		return errors.New("goreecloud dns: trust-anchor rollover fingerprint must be SHA-256 hexadecimal")
	}
	for _, char := range state.Fingerprint {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return errors.New("goreecloud dns: trust-anchor rollover fingerprint must be lowercase SHA-256 hexadecimal")
		}
	}
	firstSeen, err := time.Parse(time.RFC3339Nano, state.FirstSeenAt)
	if err != nil {
		return errors.New("goreecloud dns: rollover first_seen_at must be RFC3339Nano")
	}
	lastSeen, err := time.Parse(time.RFC3339Nano, state.LastSeenAt)
	if err != nil {
		return errors.New("goreecloud dns: rollover last_seen_at must be RFC3339Nano")
	}
	holdDownUntil, err := time.Parse(time.RFC3339Nano, state.HoldDownUntil)
	if err != nil {
		return errors.New("goreecloud dns: rollover hold_down_until must be RFC3339Nano")
	}
	if lastSeen.Before(firstSeen) {
		return errors.New("goreecloud dns: rollover last_seen_at precedes first_seen_at")
	}
	if !holdDownUntil.After(firstSeen) {
		return errors.New("goreecloud dns: rollover hold-down must end after first observation")
	}
	return nil
}
