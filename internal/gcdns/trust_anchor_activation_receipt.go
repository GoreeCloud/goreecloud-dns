package gcdns

import (
	"errors"
	"time"
)

const TrustAnchorActivationReceiptSchemaV1 = "goreecloud-beacon-trust-anchor-activation-receipt/v1"

// TrustAnchorActivationReceipt is privacy-safe audit evidence for one explicit
// trust-anchor activation. It contains fingerprints and review provenance only,
// never DNS query data or resolver client information.
type TrustAnchorActivationReceipt struct {
	Schema               string `json:"schema"`
	ActivatedAt          string `json:"activated_at"`
	ReviewedAt           string `json:"reviewed_at"`
	EvidenceSource       string `json:"evidence_source"`
	PreviousFingerprint  string `json:"previous_fingerprint"`
	ActivatedFingerprint string `json:"activated_fingerprint"`
}

// ActivateReviewedPendingTrustAnchorWithRecovery captures an emergency recovery
// point before activation and returns an audit receipt after the exact reviewed
// candidate becomes active. It does not persist either record automatically.
func ActivateReviewedPendingTrustAnchorWithRecovery(store *TrustAnchorStore, state TrustAnchorState, review TrustAnchorTransitionReview, expectedFingerprint string, now time.Time) (TrustAnchorState, TrustAnchorRecoveryPoint, TrustAnchorActivationReceipt, error) {
	if now.IsZero() {
		return TrustAnchorState{}, TrustAnchorRecoveryPoint{}, TrustAnchorActivationReceipt{}, errors.New("goreecloud dns: trust-anchor activation time is required")
	}
	recovery, err := BuildTrustAnchorRecoveryPoint(state, now)
	if err != nil {
		return TrustAnchorState{}, TrustAnchorRecoveryPoint{}, TrustAnchorActivationReceipt{}, err
	}
	activated, err := ActivateReviewedPendingTrustAnchor(store, state, review, expectedFingerprint)
	if err != nil {
		return TrustAnchorState{}, TrustAnchorRecoveryPoint{}, TrustAnchorActivationReceipt{}, err
	}
	activatedFingerprint, err := trustAnchorFingerprint(activated.Active)
	if err != nil {
		return TrustAnchorState{}, TrustAnchorRecoveryPoint{}, TrustAnchorActivationReceipt{}, err
	}
	if activatedFingerprint != recovery.PendingFingerprint {
		return TrustAnchorState{}, TrustAnchorRecoveryPoint{}, TrustAnchorActivationReceipt{}, errors.New("goreecloud dns: activated trust-anchor set does not match captured recovery transition")
	}
	receipt := TrustAnchorActivationReceipt{
		Schema:               TrustAnchorActivationReceiptSchemaV1,
		ActivatedAt:          now.UTC().Format(time.RFC3339Nano),
		ReviewedAt:           review.ReviewedAt,
		EvidenceSource:       review.EvidenceSource,
		PreviousFingerprint:  recovery.ActiveFingerprint,
		ActivatedFingerprint: activatedFingerprint,
	}
	return activated, recovery, receipt, nil
}
