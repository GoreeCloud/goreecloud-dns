package gcdns

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPolicyFilterListTrustedKeyStoreRotationAndRevocation(t *testing.T) {
	clock := time.Date(2026, 9, 4, 18, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "filter-list-trusted-keys.json")
	store, err := NewPolicyFilterListTrustedKeyStore(path, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	state := BootstrapPolicyFilterListTrustedKeyState(clock)
	oldPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	oldPublic := append(ed25519.PublicKey(nil), oldPrivate.Public().(ed25519.PublicKey)...)
	nextPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	nextPublic := append(ed25519.PublicKey(nil), nextPrivate.Public().(ed25519.PublicKey)...)

	state, err = store.AddKey(state, "publisher-2026-a", oldPublic, "reviewed bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Hour)
	state, err = store.AddKey(state, "publisher-2026-b", nextPublic, "reviewed rotation")
	if err != nil {
		t.Fatal(err)
	}
	if _, duplicateErr := store.AddKey(state, "publisher-alias", oldPublic, "alias attempt"); duplicateErr == nil {
		t.Fatal("duplicate public key unexpectedly accepted under another key ID")
	}

	clock = clock.Add(time.Hour)
	state, err = store.RevokeKey(state, "publisher-2026-a", "rotation completed")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Save(state); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	active, err := loaded.ActiveKeys()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := active["publisher-2026-a"]; ok {
		t.Fatal("revoked filter-list signing key remained active")
	}
	if got := active["publisher-2026-b"]; !bytes.Equal(got, nextPublic) {
		t.Fatal("rotated filter-list signing key is not active")
	}

	oldMetadata, oldSignature, content := signedFilterListMetadataForKey(t, "publisher-2026-a", oldPrivate, clock)
	if _, verifyErr := VerifyPolicyFilterListSignedMetadata(oldMetadata, oldSignature, content, active, clock); verifyErr == nil || !strings.Contains(verifyErr.Error(), "not trusted") {
		t.Fatalf("revoked signing key verification error = %v", verifyErr)
	}
	nextMetadata, nextSignature, content := signedFilterListMetadataForKey(t, "publisher-2026-b", nextPrivate, clock)
	if _, verifyErr := VerifyPolicyFilterListSignedMetadata(nextMetadata, nextSignature, content, active, clock); verifyErr != nil {
		t.Fatalf("rotated signing key did not verify: %v", verifyErr)
	}
}

func TestPolicyFilterListTrustedKeyStoreRejectsReuseAndTampering(t *testing.T) {
	clock := time.Date(2026, 9, 4, 20, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "filter-list-trusted-keys.json")
	store, err := NewPolicyFilterListTrustedKeyStore(path, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	publicKey := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	state, err := store.AddKey(BootstrapPolicyFilterListTrustedKeyState(clock), "publisher-primary", publicKey, "reviewed bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Hour)
	state, err = store.RevokeKey(state, "publisher-primary", "emergency revocation")
	if err != nil {
		t.Fatal(err)
	}
	replacement := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{10}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if _, reuseErr := store.AddKey(state, "publisher-primary", replacement, "reuse attempt"); reuseErr == nil {
		t.Fatal("revoked key ID was unexpectedly reusable")
	}
	active, err := state.ActiveKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 0 {
		t.Fatalf("emergency revocation should fail closed with no active keys, got %d", len(active))
	}

	if err = store.Save(state); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted map[string]any
	if err = json.Unmarshal(data, &persisted); err != nil {
		t.Fatal(err)
	}
	keys, ok := persisted["keys"].([]any)
	if !ok || len(keys) != 1 {
		t.Fatal("persisted trusted-key fixture is malformed")
	}
	record, ok := keys[0].(map[string]any)
	if !ok {
		t.Fatal("persisted trusted-key record is malformed")
	}
	record["fingerprint_sha256"] = strings.Repeat("0", sha256.Size*2)
	tampered, err := json.Marshal(persisted)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, loadErr := store.Load(); loadErr == nil || !strings.Contains(loadErr.Error(), "fingerprint mismatch") {
		t.Fatalf("tampered trusted-key state error = %v", loadErr)
	}
}

func signedFilterListMetadataForKey(t *testing.T, keyID string, privateKey ed25519.PrivateKey, now time.Time) ([]byte, []byte, []byte) {
	t.Helper()
	content := []byte("example.com\n")
	contentDigest := sha256.Sum256(content)
	metadata := PolicyFilterListSignedMetadata{
		Schema:        PolicyFilterListMetadataSchemaV1,
		SourceID:      "source-a",
		SourceURI:     "https://filters.example/list.txt",
		Publisher:     "GoreeCloud acceptance fixture",
		Sequence:      42,
		IssuedAt:      now.Add(-time.Minute).Format(time.RFC3339Nano),
		ExpiresAt:     now.Add(24 * time.Hour).Format(time.RFC3339Nano),
		ContentSHA256: hex.EncodeToString(contentDigest[:]),
		KeyID:         keyID,
	}
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	return metadataBytes, ed25519.Sign(privateKey, metadataBytes), content
}
