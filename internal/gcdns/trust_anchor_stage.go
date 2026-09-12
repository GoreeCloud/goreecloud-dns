package gcdns

import (
	"errors"
	"strings"
)

// StageApprovedTrustAnchorCandidate converts an explicitly reviewed and
// fingerprint-bound authenticated candidate into pending state only. It never
// activates the candidate; activation still requires a separate exact,
// review-bound approval step.
func StageApprovedTrustAnchorCandidate(store *TrustAnchorStore, state TrustAnchorState, candidate AuthenticatedTrustAnchorCandidate, review TrustAnchorTransitionReview, expectedFingerprint string) (TrustAnchorState, error) {
	if store == nil {
		return TrustAnchorState{}, errors.New("goreecloud dns: trust-anchor store is required")
	}
	if err := validateTrustAnchorState(state); err != nil {
		return TrustAnchorState{}, err
	}
	if err := ValidateAuthenticatedTrustAnchorCandidate(candidate); err != nil {
		return TrustAnchorState{}, err
	}
	if !review.HoldDownComplete || !review.ManualApprovalReady {
		return TrustAnchorState{}, errors.New("goreecloud dns: trust-anchor transition review is not ready for explicit staging")
	}
	candidateSource := strings.TrimSpace(candidate.Source)
	if candidateSource == "" || strings.TrimSpace(review.EvidenceSource) != candidateSource {
		return TrustAnchorState{}, errors.New("goreecloud dns: trust-anchor transition review source does not match authenticated candidate")
	}
	fingerprint, err := trustAnchorFingerprint(trustAnchorRecordsFromDS(candidate.Anchors))
	if err != nil {
		return TrustAnchorState{}, err
	}
	expectedFingerprint = strings.ToLower(strings.TrimSpace(expectedFingerprint))
	if expectedFingerprint == "" || expectedFingerprint != fingerprint || review.CandidateFingerprint != fingerprint {
		return TrustAnchorState{}, errors.New("goreecloud dns: explicit trust-anchor staging fingerprint mismatch")
	}
	return store.StageUpdate(state, candidate.Anchors, candidateSource)
}
