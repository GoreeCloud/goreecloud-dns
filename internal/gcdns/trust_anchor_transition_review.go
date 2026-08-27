package gcdns

import (
	"errors"
	"strings"
	"time"
)

// TrustAnchorTransitionReview is a non-mutating gate between authenticated
// rollover evidence and an explicit operator approval decision. Eligibility
// never activates, stages, revokes, removes, or persists trust anchors.
type TrustAnchorTransitionReview struct {
	CandidateFingerprint string `json:"candidate_fingerprint"`
	EvidenceSource       string `json:"evidence_source"`
	ReviewedAt           string `json:"reviewed_at"`
	HoldDownComplete     bool   `json:"hold_down_complete"`
	ManualApprovalReady  bool   `json:"manual_approval_ready"`
}

func BuildTrustAnchorTransitionReview(plan TrustAnchorChangePlan, evidence DNSKEYRolloverEvidence, holdDown TrustAnchorRolloverState, now time.Time) (TrustAnchorTransitionReview, error) {
	if plan.CandidateFingerprint == "" || plan.ActiveFingerprint == "" {
		return TrustAnchorTransitionReview{}, errors.New("goreecloud dns: trust-anchor change plan is incomplete")
	}
	if plan.CandidateFingerprint != holdDown.Fingerprint {
		return TrustAnchorTransitionReview{}, errors.New("goreecloud dns: hold-down fingerprint does not match candidate change plan")
	}
	if strings.TrimSpace(evidence.Source) == "" || strings.TrimSpace(evidence.ObservedAt) == "" {
		return TrustAnchorTransitionReview{}, errors.New("goreecloud dns: DNSKEY rollover evidence is incomplete")
	}
	if now.IsZero() {
		return TrustAnchorTransitionReview{}, errors.New("goreecloud dns: trust-anchor transition review time is required")
	}
	if len(plan.Additions) == 0 && len(plan.Removals) == 0 {
		return TrustAnchorTransitionReview{}, errors.New("goreecloud dns: trust-anchor change plan contains no changes")
	}
	if err := ValidateTrustAnchorDNSKEYChangeEvidence(plan, evidence); err != nil {
		return TrustAnchorTransitionReview{}, err
	}
	complete, err := TrustAnchorCandidateHoldDownComplete(holdDown, now)
	if err != nil {
		return TrustAnchorTransitionReview{}, err
	}
	return TrustAnchorTransitionReview{
		CandidateFingerprint: plan.CandidateFingerprint,
		EvidenceSource:       strings.TrimSpace(evidence.Source),
		ReviewedAt:           now.UTC().Format(time.RFC3339Nano),
		HoldDownComplete:     complete,
		ManualApprovalReady:  complete,
	}, nil
}
