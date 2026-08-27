package gcdns

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func persistenceActivationFixture(t *testing.T, now time.Time) (*TrustAnchorStore, TrustAnchorState, TrustAnchorTransitionReview) {
	t.Helper()
	store, err := NewTrustAnchorStore(filepath.Join(t.TempDir(), "anchors.json"), func() time.Time { return now })
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
	return store, staged, TrustAnchorTransitionReview{
		CandidateFingerprint: staged.Pending.Fingerprint,
		EvidenceSource:       staged.Pending.Source,
		ReviewedAt:           now.Format(time.RFC3339Nano),
		HoldDownComplete:     true,
		ManualApprovalReady:  true,
	}
}

func TestPersistReviewedTrustAnchorActivationPersistsStateAndAudit(t *testing.T) {
	now := time.Date(2026, 8, 27, 15, 0, 0, 0, time.UTC)
	store, staged, review := persistenceActivationFixture(t, now)
	lifecycle, err := NewTrustAnchorLifecycleLog(filepath.Join(t.TempDir(), "lifecycle.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := PersistReviewedTrustAnchorActivation(store, lifecycle, staged, review, staged.Pending.Fingerprint, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.AuditReconciliationRequired || result.State.Pending != nil || result.LifecycleEvent.EventType != "activation" {
		t.Fatalf("unexpected persistence result: %+v", result)
	}
	persisted, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := trustAnchorFingerprint(persisted.Active)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != result.Receipt.ActivatedFingerprint || result.LifecycleEvent.CurrentFingerprint != fingerprint {
		t.Fatal("persisted state, activation receipt, and lifecycle event are not fingerprint-bound")
	}
	events, err := lifecycle.Load()
	if err != nil || len(events) != 1 {
		t.Fatalf("unexpected lifecycle history: events=%d err=%v", len(events), err)
	}
}

func TestAppendOrReconcileTrustAnchorActivationIsIdempotent(t *testing.T) {
	now := time.Date(2026, 8, 27, 15, 0, 0, 0, time.UTC)
	store, staged, review := persistenceActivationFixture(t, now)
	lifecycle, err := NewTrustAnchorLifecycleLog(filepath.Join(t.TempDir(), "lifecycle.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, receipt, err := ActivateReviewedPendingTrustAnchorWithRecovery(store, staged, review, staged.Pending.Fingerprint, now)
	if err != nil {
		t.Fatal(err)
	}
	first, err := AppendOrReconcileTrustAnchorActivation(lifecycle, receipt)
	if err != nil {
		t.Fatal(err)
	}
	second, err := AppendOrReconcileTrustAnchorActivation(lifecycle, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if first.EventHash != second.EventHash || first.Sequence != second.Sequence {
		t.Fatal("exact activation audit replay created a different lifecycle event")
	}
	events, err := lifecycle.Load()
	if err != nil || len(events) != 1 {
		t.Fatalf("idempotent replay changed lifecycle history: events=%d err=%v", len(events), err)
	}
}
