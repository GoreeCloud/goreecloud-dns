package gcdns

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPolicyFilterListLifecycleApplyAndRollback(t *testing.T) {
	now := time.Date(2026, 8, 30, 2, 30, 0, 0, time.UTC)
	lifecycle := NewPolicyFilterListLifecycle()
	first := testPolicyFilterListSnapshot(t, "source-a", 1, []byte("example.com\n"), now)
	second := testPolicyFilterListSnapshot(t, "source-a", 2, []byte("example.net\n"), now)

	if err := lifecycle.Apply(first, now); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Apply(second, now); err != nil {
		t.Fatal(err)
	}
	active, ok := lifecycle.Active()
	if !ok || active.Provenance.Sequence != 2 {
		t.Fatalf("unexpected active snapshot: ok=%v snapshot=%+v", ok, active.Provenance)
	}

	if err := lifecycle.Rollback(first.Provenance.ContentSHA256, now); err != nil {
		t.Fatal(err)
	}
	active, ok = lifecycle.Active()
	if !ok || active.Provenance.Sequence != 1 || string(active.Content) != "example.com\n" {
		t.Fatalf("unexpected rollback result: ok=%v snapshot=%+v", ok, active)
	}
}

func TestPolicyFilterListLifecycleRejectsNonMonotonicUpdate(t *testing.T) {
	now := time.Date(2026, 8, 30, 2, 30, 0, 0, time.UTC)
	lifecycle := NewPolicyFilterListLifecycle()
	if err := lifecycle.Apply(testPolicyFilterListSnapshot(t, "source-a", 2, []byte("example.com\n"), now), now); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Apply(testPolicyFilterListSnapshot(t, "source-a", 2, []byte("example.net\n"), now), now); err == nil {
		t.Fatal("non-monotonic filter-list update unexpectedly accepted")
	}
}

func TestPolicyFilterListLifecycleRejectsSourceSwitch(t *testing.T) {
	now := time.Date(2026, 8, 30, 2, 30, 0, 0, time.UTC)
	lifecycle := NewPolicyFilterListLifecycle()
	if err := lifecycle.Apply(testPolicyFilterListSnapshot(t, "source-a", 1, []byte("example.com\n"), now), now); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Apply(testPolicyFilterListSnapshot(t, "source-b", 2, []byte("example.net\n"), now), now); err == nil {
		t.Fatal("filter-list source identity switch unexpectedly accepted")
	}
}

func TestPolicyFilterListLifecycleRejectsExpiredSnapshot(t *testing.T) {
	now := time.Date(2026, 8, 30, 2, 30, 0, 0, time.UTC)
	snapshot := testPolicyFilterListSnapshot(t, "source-a", 1, []byte("example.com\n"), now)
	snapshot.Provenance.ExpiresAt = now
	if err := NewPolicyFilterListLifecycle().Apply(snapshot, now); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired snapshot error = %v", err)
	}
}

func TestPolicyFilterListLifecycleRejectsDigestMismatch(t *testing.T) {
	now := time.Date(2026, 8, 30, 2, 30, 0, 0, time.UTC)
	snapshot := testPolicyFilterListSnapshot(t, "source-a", 1, []byte("example.com\n"), now)
	snapshot.Content = []byte("tampered.example\n")
	if err := NewPolicyFilterListLifecycle().Apply(snapshot, now); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("digest mismatch error = %v", err)
	}
}

func TestPolicyFilterListLifecycleRejectsCredentialedOrPlaintextSourceURI(t *testing.T) {
	now := time.Date(2026, 8, 30, 2, 30, 0, 0, time.UTC)
	for _, sourceURI := range []string{
		"http://filters.example/list.txt",
		"https://user:secret@filters.example/list.txt",
	} {
		snapshot := testPolicyFilterListSnapshot(t, "source-a", 1, []byte("example.com\n"), now)
		snapshot.Provenance.SourceURI = sourceURI
		if err := NewPolicyFilterListLifecycle().Apply(snapshot, now); err == nil {
			t.Fatalf("unsafe source URI %q unexpectedly accepted", sourceURI)
		}
	}
}

func TestPolicyFilterListLifecycleActiveReturnsDefensiveCopy(t *testing.T) {
	now := time.Date(2026, 8, 30, 2, 30, 0, 0, time.UTC)
	lifecycle := NewPolicyFilterListLifecycle()
	if err := lifecycle.Apply(testPolicyFilterListSnapshot(t, "source-a", 1, []byte("example.com\n"), now), now); err != nil {
		t.Fatal(err)
	}
	active, ok := lifecycle.Active()
	if !ok {
		t.Fatal("missing active snapshot")
	}
	active.Content[0] = 'X'
	again, _ := lifecycle.Active()
	if string(again.Content) != "example.com\n" {
		t.Fatal("caller mutated lifecycle-owned snapshot content")
	}
}

func testPolicyFilterListSnapshot(t *testing.T, sourceID string, sequence uint64, content []byte, now time.Time) PolicyFilterListSnapshot {
	t.Helper()
	contentDigest := sha256.Sum256(content)
	metadataDigest := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%x", sourceID, sequence, contentDigest)))
	return PolicyFilterListSnapshot{
		Provenance: PolicyFilterListProvenance{
			SourceID:       sourceID,
			SourceURI:      "https://filters.example/list.txt",
			Publisher:      "GoreeCloud acceptance fixture",
			Sequence:       sequence,
			IssuedAt:       now.Add(-time.Minute),
			ExpiresAt:      now.Add(24 * time.Hour),
			MetadataSHA256: fmt.Sprintf("%x", metadataDigest),
			ContentSHA256:  fmt.Sprintf("%x", contentDigest),
		},
		Content: append([]byte(nil), content...),
	}
}
