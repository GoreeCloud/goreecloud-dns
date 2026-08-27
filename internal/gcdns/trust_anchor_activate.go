package gcdns

import (
	"errors"
	"strings"
	"time"
)

// ActivateReviewedPendingTrustAnchor is the explicit activation boundary for a
// staged trust-anchor update. It requires the same review source and exact
// candidate fingerprint that authorized staging. It does not acquire evidence
// or create a review implicitly.
func ActivateReviewedPendingTrustAnchor(store *TrustAnchorStore, state TrustAnchorState, review TrustAnchorTransitionReview, expectedFingerprint string) (TrustAnchorState, error) {
	if store == nil {
		return TrustAnchorState{}, errors.New("goreecloud dns: trust-anchor store is required")
	}
	if err := validateTrustAnchorState(state); err != nil {
		return TrustAnchorState{}, err
	}
	if state.Pending == nil {
		return TrustAnchorState{}, errors.New("goreecloud dns: no trust-anchor update is pending")
	}
	if !review.HoldDownComplete || !review.ManualApprovalReady {
		return TrustAnchorState{}, errors.New("goreecloud dns: trust-anchor transition review is not ready for activation")
	}
	if _, err := time.Parse(time.RFC3339Nano, review.ReviewedAt); err != nil {
		return TrustAnchorState{}, errors.New("goreecloud dns: trust-anchor transition review time is invalid")
	}
	if strings.TrimSpace(review.EvidenceSource) == "" || strings.TrimSpace(review.EvidenceSource) != state.Pending.Source {
		return TrustAnchorState{}, errors.New("goreecloud dns: trust-anchor activation review source mismatch")
	}
	expectedFingerprint = strings.ToLower(strings.TrimSpace(expectedFingerprint))
	if expectedFingerprint == "" || expectedFingerprint != state.Pending.Fingerprint || review.CandidateFingerprint != state.Pending.Fingerprint {
		return TrustAnchorState{}, errors.New("goreecloud dns: trust-anchor activation fingerprint mismatch")
	}
	return store.ApprovePending(state, expectedFingerprint)
}
