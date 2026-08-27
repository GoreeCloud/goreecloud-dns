package gcdns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestTrustAnchorLifecycleLogAppendsHashChainedActivationEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit", "trust-anchor.jsonl")
	log, err := NewTrustAnchorLifecycleLog(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	firstReceipt := TrustAnchorActivationReceipt{
		Schema:               TrustAnchorActivationReceiptSchemaV1,
		ActivatedAt:          now.Format(time.RFC3339Nano),
		ReviewedAt:           now.Format(time.RFC3339Nano),
		EvidenceSource:       "authenticated-source-a",
		PreviousFingerprint:  strings.Repeat("a", 64),
		ActivatedFingerprint: strings.Repeat("b", 64),
	}
	first, err := log.AppendActivation(firstReceipt)
	if err != nil {
		t.Fatal(err)
	}
	secondReceipt := firstReceipt
	secondReceipt.ActivatedAt = now.Add(time.Minute).Format(time.RFC3339Nano)
	secondReceipt.EvidenceSource = "authenticated-source-b"
	secondReceipt.PreviousFingerprint = strings.Repeat("b", 64)
	secondReceipt.ActivatedFingerprint = strings.Repeat("c", 64)
	second, err := log.AppendActivation(secondReceipt)
	if err != nil {
		t.Fatal(err)
	}
	if first.Sequence != 1 || second.Sequence != 2 || second.PreviousEventHash != first.EventHash {
		t.Fatalf("unexpected hash chain: first=%+v second=%+v", first, second)
	}
	events, err := log.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].EventHash != second.EventHash {
		t.Fatalf("unexpected loaded lifecycle events: %+v", events)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("lifecycle log mode=%#o", info.Mode().Perm())
	}
}

func TestTrustAnchorLifecycleLogRejectsTamperedHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trust-anchor.jsonl")
	log, err := NewTrustAnchorLifecycleLog(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	_, err = log.AppendActivation(TrustAnchorActivationReceipt{
		Schema:               TrustAnchorActivationReceiptSchemaV1,
		ActivatedAt:          now.Format(time.RFC3339Nano),
		ReviewedAt:           now.Format(time.RFC3339Nano),
		EvidenceSource:       "authenticated-source",
		PreviousFingerprint:  strings.Repeat("a", 64),
		ActivatedFingerprint: strings.Repeat("b", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), strings.Repeat("b", 64), strings.Repeat("c", 64), 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Load(); err == nil {
		t.Fatal("tampered trust-anchor lifecycle history unexpectedly validated")
	}
}

func TestTrustAnchorLifecycleLogRecordsCompletedRecovery(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	store, err := NewTrustAnchorStore(filepath.Join(t.TempDir(), "anchors.json"), func() time.Time { return now })
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
	restored, err := RestoreTrustAnchorRecoveryPoint(store, activated, recovery, currentFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	log, err := NewTrustAnchorLifecycleLog(filepath.Join(t.TempDir(), "trust-anchor.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	event, err := log.AppendRecovery(recovery, restored, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if event.EventType != "recovery" || event.PreviousFingerprint != recovery.PendingFingerprint || event.CurrentFingerprint != recovery.ActiveFingerprint {
		t.Fatalf("unexpected recovery lifecycle event: %+v", event)
	}
}
