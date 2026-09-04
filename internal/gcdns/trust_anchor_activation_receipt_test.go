package gcdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestActivateReviewedPendingTrustAnchorWithRecoveryReturnsBoundEvidence(t *testing.T) {
	now := time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC)
	store, err := NewTrustAnchorStore(t.TempDir()+"/anchors.json", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	state := BootstrapTrustAnchorState(now)
	candidateAnchors := make([]*dns.DS, 0, len(RootTrustAnchors()))
	for _, anchor := range RootTrustAnchors() {
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

	activated, recovery, receipt, err := ActivateReviewedPendingTrustAnchorWithRecovery(store, staged, review, staged.Pending.Fingerprint, now)
	if err != nil {
		t.Fatal(err)
	}
	if activated.Pending != nil {
		t.Fatal("activation unexpectedly retained pending trust-anchor state")
	}
	if recovery.PendingFingerprint != receipt.ActivatedFingerprint {
		t.Fatal("activation receipt does not bind to captured recovery transition")
	}
	if recovery.ActiveFingerprint != receipt.PreviousFingerprint {
		t.Fatal("activation receipt does not identify the pre-activation trust-anchor set")
	}
	if receipt.Schema != TrustAnchorActivationReceiptSchemaV1 || receipt.EvidenceSource != review.EvidenceSource || receipt.ReviewedAt != review.ReviewedAt {
		t.Fatalf("unexpected activation receipt: %+v", receipt)
	}
}

func TestActivateReviewedPendingTrustAnchorWithRecoveryFailsBeforeEvidenceOnBadApproval(t *testing.T) {
	now := time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC)
	store, err := NewTrustAnchorStore(t.TempDir()+"/anchors.json", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	state := BootstrapTrustAnchorState(now)
	candidateAnchors := make([]*dns.DS, 0, len(RootTrustAnchors()))
	for _, anchor := range RootTrustAnchors() {
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
	if _, _, _, err := ActivateReviewedPendingTrustAnchorWithRecovery(store, staged, review, "wrong", now); err == nil {
		t.Fatal("bad approval fingerprint unexpectedly produced activation evidence")
	}
}
