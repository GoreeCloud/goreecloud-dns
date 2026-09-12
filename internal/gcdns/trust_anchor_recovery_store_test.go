package gcdns

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestTrustAnchorRecoveryStoreSaveLoadAndIdempotentReplay(t *testing.T) {
	recovery := buildStoredTrustAnchorRecoveryPoint(t)
	store, err := NewTrustAnchorRecoveryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	path, err := store.Save(recovery)
	if err != nil {
		t.Fatal(err)
	}
	replayedPath, err := store.Save(recovery)
	if err != nil {
		t.Fatal(err)
	}
	if replayedPath != path {
		t.Fatalf("idempotent recovery path = %q, want %q", replayedPath, path)
	}
	loaded, err := store.Load(recovery.PendingFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, recovery) {
		t.Fatalf("loaded recovery point differs: got %+v want %+v", loaded, recovery)
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if !info.Mode().IsRegular() {
		t.Fatal("persisted recovery point is not a regular file")
	}
}

func TestTrustAnchorRecoveryStoreRejectsConflictingImmutableRecord(t *testing.T) {
	recovery := buildStoredTrustAnchorRecoveryPoint(t)
	store, err := NewTrustAnchorRecoveryStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path, err := store.Save(recovery)
	if err != nil {
		t.Fatal(err)
	}

	conflicting := recovery
	conflicting.CreatedAt = time.Date(2026, 8, 27, 9, 31, 0, 0, time.UTC).Format(time.RFC3339Nano)
	encoded, err := json.MarshalIndent(conflicting, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(recovery); err == nil {
		t.Fatal("conflicting immutable recovery record unexpectedly accepted")
	}
}

func buildStoredTrustAnchorRecoveryPoint(t *testing.T) TrustAnchorRecoveryPoint {
	t.Helper()
	now := time.Date(2026, 8, 27, 9, 30, 0, 0, time.UTC)
	state := BootstrapTrustAnchorState(now)
	store, err := NewTrustAnchorStore(t.TempDir()+"/anchors.json", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
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
	return recovery
}
