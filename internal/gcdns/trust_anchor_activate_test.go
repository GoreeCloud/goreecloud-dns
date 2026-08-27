package gcdns

import (
	"testing"
	"time"
)

func TestActivateReviewedPendingTrustAnchorRequiresExactReviewBinding(t *testing.T) {
	now := time.Date(2026, 8, 27, 5, 0, 0, 0, time.UTC)
	store, err := NewTrustAnchorStore(t.TempDir()+"/anchors.json", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	state := BootstrapTrustAnchorState(now)
	anchors := RootTrustAnchors()
	candidateAnchors := make([]*dns.DS, 0, len(anchors))
	for _, anchor := range anchors {
		copy := *anchor
		candidateAnchors = append(candidateAnchors, &copy)
	}
	candidateAnchors[0].Digest = candidateAnchors[0].Digest[:len(candidateAnchors[0].Digest)-1] + "0"
	staged, err := store.StageUpdate(state, candidateAnchors, "authenticated-test-source")
	if err != nil {
		t.Fatal(err)
	}
	review := TrustAnchorTransitionReview{
		CandidateFingerprint: staged.Pending.Fingerprint,
		EvidenceSource:       staged.Pending.Source,
		ReviewedAt:           now.Format(time.RFC3339Nano),
		HoldDownComplete:     true,
		ManualApprovalReady:  true,
	}

	wrongSource := review
	wrongSource.EvidenceSource = "different-source"
	if _, activateErr := ActivateReviewedPendingTrustAnchor(store, staged, wrongSource, staged.Pending.Fingerprint); activateErr == nil {
		t.Fatal("mismatched review source unexpectedly activated pending trust anchors")
	}
	activated, err := ActivateReviewedPendingTrustAnchor(store, staged, review, staged.Pending.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if activated.Pending != nil || !sameTrustAnchorSet(activated.Active, trustAnchorRecordsFromDS(candidateAnchors)) {
		t.Fatal("review-bound activation did not activate exactly the staged trust-anchor set")
	}
}
