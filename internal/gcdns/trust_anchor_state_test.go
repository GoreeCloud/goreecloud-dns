package gcdns

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestBootstrapTrustAnchorState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 24, 16, 0, 0, 0, time.UTC)
	state := BootstrapTrustAnchorState(now)
	if state.Schema != trustAnchorStateSchema {
		t.Fatalf("schema = %q", state.Schema)
	}
	if state.UpdatedAt != now.Format(time.RFC3339Nano) {
		t.Fatalf("updated_at = %q", state.UpdatedAt)
	}
	if len(state.Active) != len(RootTrustAnchors()) {
		t.Fatalf("active anchors = %d, want %d", len(state.Active), len(RootTrustAnchors()))
	}
	if state.Pending != nil {
		t.Fatal("bootstrap state unexpectedly contains pending update")
	}
}

func TestTrustAnchorStoreRoundTripAndPermissions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "state", "trust-anchors.json")
	now := time.Date(2026, 8, 24, 16, 0, 0, 0, time.UTC)
	store, err := NewTrustAnchorStore(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	state := BootstrapTrustAnchorState(now)
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !sameTrustAnchorSet(loaded.Active, state.Active) {
		t.Fatal("round-tripped active trust anchors changed")
	}
}

func TestTrustAnchorUpdateRequiresExplicitFingerprintApproval(t *testing.T) {
	t.Parallel()

	times := []time.Time{
		time.Date(2026, 8, 24, 16, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 24, 16, 5, 0, 0, time.UTC),
		time.Date(2026, 8, 24, 16, 10, 0, 0, time.UTC),
	}
	index := 0
	store, err := NewTrustAnchorStore(filepath.Join(t.TempDir(), "anchors.json"), func() time.Time {
		value := times[index]
		if index < len(times)-1 {
			index++
		}
		return value
	})
	if err != nil {
		t.Fatal(err)
	}
	state := BootstrapTrustAnchorState(times[0])
	candidate := append(RootTrustAnchors(), &dns.DS{
		Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
		KeyTag:     50000,
		Algorithm:  dnssecAlgorithmECDSAP256SHA256,
		DigestType: dns.SHA256,
		Digest:     "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
	})
	staged, err := store.StageUpdate(state, candidate, "authenticated-operator-input")
	if err != nil {
		t.Fatal(err)
	}
	if staged.Pending == nil || staged.Pending.Fingerprint == "" {
		t.Fatal("staged update missing fingerprint")
	}
	if len(staged.Active) != len(state.Active) {
		t.Fatal("staging update changed active trust anchors")
	}
	if _, err := store.ApprovePending(staged, "wrong-fingerprint"); err == nil {
		t.Fatal("mismatched approval fingerprint unexpectedly accepted")
	}
	approved, err := store.ApprovePending(staged, staged.Pending.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Pending != nil {
		t.Fatal("approved state still contains pending update")
	}
	if len(approved.Active) != len(candidate) {
		t.Fatalf("approved anchors = %d, want %d", len(approved.Active), len(candidate))
	}
}

func TestTrustAnchorUpdateCanBeRejectedWithoutChangingActiveSet(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 24, 16, 0, 0, 0, time.UTC)
	store, err := NewTrustAnchorStore(filepath.Join(t.TempDir(), "anchors.json"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	state := BootstrapTrustAnchorState(now)
	candidate := []*dns.DS{RootTrustAnchors()[0]}
	staged, err := store.StageUpdate(state, candidate, "authenticated-operator-input")
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := store.RejectPending(staged)
	if err != nil {
		t.Fatal(err)
	}
	if rejected.Pending != nil {
		t.Fatal("rejected state still contains pending update")
	}
	if !sameTrustAnchorSet(rejected.Active, state.Active) {
		t.Fatal("rejecting pending update changed active anchors")
	}
}

func TestTrustAnchorStoreRejectsUnchangedUpdate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 24, 16, 0, 0, 0, time.UTC)
	store, err := NewTrustAnchorStore(filepath.Join(t.TempDir(), "anchors.json"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	state := BootstrapTrustAnchorState(now)
	if _, err := store.StageUpdate(state, RootTrustAnchors(), "authenticated-operator-input"); err == nil {
		t.Fatal("unchanged trust-anchor set unexpectedly staged")
	}
}

func TestTrustAnchorStateRejectsUnapprovedAlgorithmsAndNonRootNames(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 24, 16, 0, 0, 0, time.UTC)
	state := BootstrapTrustAnchorState(now)
	state.Active[0].Algorithm = dnssecAlgorithmRSASHA1
	if err := validateTrustAnchorState(state); err == nil {
		t.Fatal("SHA-1 DS trust anchor unexpectedly accepted")
	}

	state = BootstrapTrustAnchorState(now)
	state.Active[0].Name = "example."
	if err := validateTrustAnchorState(state); err == nil {
		t.Fatal("non-root lifecycle trust anchor unexpectedly accepted")
	}
}

func TestTrustAnchorPendingFingerprintIsTamperEvident(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 24, 16, 0, 0, 0, time.UTC)
	store, err := NewTrustAnchorStore(filepath.Join(t.TempDir(), "anchors.json"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	state := BootstrapTrustAnchorState(now)
	candidate := []*dns.DS{RootTrustAnchors()[0]}
	staged, err := store.StageUpdate(state, candidate, "authenticated-operator-input")
	if err != nil {
		t.Fatal(err)
	}
	staged.Pending.Anchors[0].Digest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := validateTrustAnchorState(staged); err == nil {
		t.Fatal("tampered pending trust-anchor update unexpectedly validated")
	}
}
