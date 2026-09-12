package gcdns

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func isolatedRecoveryRehearsalFixture(t *testing.T, root string, now time.Time) (*TrustAnchorStore, *TrustAnchorLifecycleLog, *TrustAnchorRecoveryStore, TrustAnchorState, TrustAnchorTransitionReview) {
	t.Helper()
	store, err := NewTrustAnchorStore(filepath.Join(root, "state", "anchors.json"), func() time.Time { return now.Add(time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := NewTrustAnchorLifecycleLog(filepath.Join(root, "audit", "lifecycle.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	recoveryStore, err := NewTrustAnchorRecoveryStore(filepath.Join(root, "recovery"))
	if err != nil {
		t.Fatal(err)
	}
	state := BootstrapTrustAnchorState(now)
	candidateAnchors := make([]*dns.DS, 0, len(RootTrustAnchors()))
	for _, anchor := range RootTrustAnchors() {
		copy := *anchor
		candidateAnchors = append(candidateAnchors, &copy)
	}
	last := candidateAnchors[0].Digest[len(candidateAnchors[0].Digest)-1]
	if last == '0' {
		candidateAnchors[0].Digest = candidateAnchors[0].Digest[:len(candidateAnchors[0].Digest)-1] + "1"
	} else {
		candidateAnchors[0].Digest = candidateAnchors[0].Digest[:len(candidateAnchors[0].Digest)-1] + "0"
	}
	staged, err := store.StageUpdate(state, candidateAnchors, "authenticated-rehearsal-source")
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
	return store, lifecycle, recoveryStore, staged, review
}

func TestRunIsolatedTrustAnchorRecoveryRehearsalRestoresAndAudits(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 8, 28, 20, 30, 0, 0, time.UTC)
	store, lifecycle, recoveryStore, staged, review := isolatedRecoveryRehearsalFixture(t, root, now)
	previousFingerprint, err := trustAnchorFingerprint(staged.Active)
	if err != nil {
		t.Fatal(err)
	}
	candidateFingerprint := staged.Pending.Fingerprint

	receipt, err := RunIsolatedTrustAnchorRecoveryRehearsal(
		root,
		store,
		lifecycle,
		recoveryStore,
		staged,
		review,
		candidateFingerprint,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Schema != TrustAnchorRecoveryRehearsalReceiptSchemaV1 || receipt.PreviousFingerprint != previousFingerprint || receipt.CandidateFingerprint != candidateFingerprint || receipt.FinalFingerprint != previousFingerprint {
		t.Fatalf("unexpected recovery rehearsal receipt identity: %+v", receipt)
	}
	if !receipt.RecoveryEvidencePersisted || !receipt.CandidateActivated || !receipt.ActivationAudited || !receipt.PreviousAnchorsRestored || !receipt.RecoveryAudited || !receipt.LifecycleVerified {
		t.Fatalf("incomplete recovery rehearsal evidence: %+v", receipt)
	}
	if receipt.ActivationAuditReconciliationRequired || receipt.RecoveryAuditReconciliationRequired || receipt.ProductionCutoverAuthorized {
		t.Fatalf("unsafe recovery rehearsal receipt: %+v", receipt)
	}
	persisted, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	finalFingerprint, err := trustAnchorFingerprint(persisted.Active)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Pending != nil || finalFingerprint != previousFingerprint {
		t.Fatal("rehearsal did not leave the isolated state at the previous trust-anchor set")
	}
	events, err := lifecycle.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].EventType != "activation" || events[1].EventType != "recovery" || events[1].PreviousEventHash != events[0].EventHash {
		t.Fatalf("unexpected rehearsal lifecycle chain: %+v", events)
	}
}

func TestRunIsolatedTrustAnchorRecoveryRehearsalRejectsStoreOutsideScope(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	now := time.Date(2026, 8, 28, 20, 31, 0, 0, time.UTC)
	_, lifecycle, recoveryStore, staged, review := isolatedRecoveryRehearsalFixture(t, root, now)
	store, err := NewTrustAnchorStore(filepath.Join(outside, "anchors.json"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}

	if _, err := RunIsolatedTrustAnchorRecoveryRehearsal(root, store, lifecycle, recoveryStore, staged, review, staged.Pending.Fingerprint, now); err == nil {
		t.Fatal("rehearsal unexpectedly accepted a trust-anchor state store outside its isolated root")
	}
	if _, err := os.Stat(filepath.Join(outside, "anchors.json")); !os.IsNotExist(err) {
		t.Fatalf("scope rejection unexpectedly wrote outside rehearsal root: %v", err)
	}
}

func TestRunIsolatedTrustAnchorRecoveryRehearsalRejectsSymlinkedStorePath(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("symbolic-link semantics vary on Windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	now := time.Date(2026, 8, 28, 20, 32, 0, 0, time.UTC)
	link := filepath.Join(root, "linked")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	store, err := NewTrustAnchorStore(filepath.Join(link, "anchors.json"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := NewTrustAnchorLifecycleLog(filepath.Join(root, "audit", "lifecycle.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	recoveryStore, err := NewTrustAnchorRecoveryStore(filepath.Join(root, "recovery"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, staged, review := isolatedRecoveryRehearsalFixture(t, t.TempDir(), now)

	if _, err := RunIsolatedTrustAnchorRecoveryRehearsal(root, store, lifecycle, recoveryStore, staged, review, staged.Pending.Fingerprint, now); err == nil {
		t.Fatal("rehearsal unexpectedly accepted a symbolic-link store path")
	}
}
