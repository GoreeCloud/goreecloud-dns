package gcdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestTrustAnchorRecoveryPointRestoresOnlyExactActivatedCandidate(t *testing.T) {
	now := time.Date(2026, 8, 27, 8, 30, 0, 0, time.UTC)
	store, err := NewTrustAnchorStore(t.TempDir()+"/anchors.json", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	original := BootstrapTrustAnchorState(now)
	candidateAnchors := make([]*dns.DS, 0, len(RootTrustAnchors()))
	for _, anchor := range RootTrustAnchors() {
		copy := *anchor
		candidateAnchors = append(candidateAnchors, &copy)
	}
	candidateAnchors[0].Digest = candidateAnchors[0].Digest[:len(candidateAnchors[0].Digest)-1] + "0"
	staged, err := store.StageUpdate(original, candidateAnchors, "authenticated-test-source")
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := BuildTrustAnchorRecoveryPoint(staged, now)
	if err != nil {
		t.Fatal(err)
	}
	activated, err := store.ApprovePending(staged, staged.Pending.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	currentFingerprint, err := trustAnchorFingerprint(activated.Active)
	if err != nil {
		t.Fatal(err)
	}

	if _, restoreErr := RestoreTrustAnchorRecoveryPoint(store, activated, recovery, "wrong"); restoreErr == nil {
		t.Fatal("recovery with wrong current fingerprint unexpectedly succeeded")
	}
	restored, err := RestoreTrustAnchorRecoveryPoint(store, activated, recovery, currentFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if !sameTrustAnchorSet(restored.Active, original.Active) {
		t.Fatal("recovery did not restore the exact pre-activation trust-anchor set")
	}
	if restored.Pending != nil {
		t.Fatal("recovery unexpectedly created a pending trust-anchor update")
	}
}

func TestTrustAnchorRecoveryPointRejectsNewerPendingTransition(t *testing.T) {
	now := time.Date(2026, 8, 27, 8, 30, 0, 0, time.UTC)
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
	recovery, err := BuildTrustAnchorRecoveryPoint(staged, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, restoreErr := RestoreTrustAnchorRecoveryPoint(store, staged, recovery, staged.Pending.Fingerprint); restoreErr == nil {
		t.Fatal("recovery unexpectedly ran over a pending transition")
	}
}
