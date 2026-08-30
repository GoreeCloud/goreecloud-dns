package gcdns

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestVerifyPolicyFilterListSignedMetadata(t *testing.T) {
	now := time.Date(2026, 8, 30, 3, 20, 0, 0, time.UTC)
	metadataBytes, signature, content, trusted := testSignedFilterListMetadata(t, 1, now)

	snapshot, err := VerifyPolicyFilterListSignedMetadata(metadataBytes, signature, content, trusted, now)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Provenance.SourceID != "source-a" || snapshot.Provenance.Sequence != 1 {
		t.Fatalf("unexpected verified provenance: %+v", snapshot.Provenance)
	}
	metadataDigest := sha256.Sum256(metadataBytes)
	if snapshot.Provenance.MetadataSHA256 != hex.EncodeToString(metadataDigest[:]) {
		t.Fatal("verified snapshot did not retain exact signed metadata identity")
	}
}

func TestVerifyPolicyFilterListSignedMetadataRejectsTampering(t *testing.T) {
	now := time.Date(2026, 8, 30, 3, 20, 0, 0, time.UTC)
	metadataBytes, signature, content, trusted := testSignedFilterListMetadata(t, 1, now)

	tamperedMetadata := append([]byte(nil), metadataBytes...)
	tamperedMetadata[len(tamperedMetadata)-2] ^= 1
	if _, err := VerifyPolicyFilterListSignedMetadata(tamperedMetadata, signature, content, trusted, now); err == nil {
		t.Fatal("tampered signed metadata unexpectedly verified")
	}

	tamperedContent := append([]byte(nil), content...)
	tamperedContent[0] ^= 1
	if _, err := VerifyPolicyFilterListSignedMetadata(metadataBytes, signature, tamperedContent, trusted, now); err == nil || !strings.Contains(err.Error(), "content digest mismatch") {
		t.Fatalf("tampered content error = %v", err)
	}
}

func TestVerifyPolicyFilterListSignedMetadataRejectsUntrustedKeyAndTrailingJSON(t *testing.T) {
	now := time.Date(2026, 8, 30, 3, 20, 0, 0, time.UTC)
	metadataBytes, signature, content, _ := testSignedFilterListMetadata(t, 1, now)
	if _, err := VerifyPolicyFilterListSignedMetadata(metadataBytes, signature, content, PolicyFilterListTrustedKeys{}, now); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("untrusted key error = %v", err)
	}

	trailing := append(append([]byte(nil), metadataBytes...), []byte("\n{}")...)
	if _, err := VerifyPolicyFilterListSignedMetadata(trailing, signature, content, PolicyFilterListTrustedKeys{"primary": testFilterListPublicKey()}, now); err == nil {
		t.Fatal("trailing signed metadata unexpectedly accepted")
	}
}

func TestPolicyFilterListLifecycleApplySignedUsesNormalMonotonicity(t *testing.T) {
	now := time.Date(2026, 8, 30, 3, 20, 0, 0, time.UTC)
	lifecycle := NewPolicyFilterListLifecycle()
	metadataBytes, signature, content, trusted := testSignedFilterListMetadata(t, 1, now)
	if err := lifecycle.ApplySigned(metadataBytes, signature, content, trusted, now); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.ApplySigned(metadataBytes, signature, content, trusted, now); err == nil || !strings.Contains(err.Error(), "sequence must increase") {
		t.Fatalf("replayed signed snapshot error = %v", err)
	}
}

func TestVerifyPolicyFilterListSignedMetadataRejectsUnknownFields(t *testing.T) {
	now := time.Date(2026, 8, 30, 3, 20, 0, 0, time.UTC)
	_, _, content, trusted := testSignedFilterListMetadata(t, 1, now)
	contentDigest := sha256.Sum256(content)
	metadataBytes, err := json.Marshal(map[string]any{
		"schema":         PolicyFilterListMetadataSchemaV1,
		"source_id":      "source-a",
		"source_uri":     "https://filters.example/list.txt",
		"publisher":      "GoreeCloud acceptance fixture",
		"sequence":       uint64(1),
		"issued_at":      now.Add(-time.Minute).Format(time.RFC3339Nano),
		"expires_at":     now.Add(24 * time.Hour).Format(time.RFC3339Nano),
		"content_sha256": hex.EncodeToString(contentDigest[:]),
		"key_id":         "primary",
		"unexpected":     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	signature := ed25519.Sign(privateKey, metadataBytes)
	if _, err := VerifyPolicyFilterListSignedMetadata(metadataBytes, signature, content, trusted, now); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown-field error = %v", err)
	}
}

func testSignedFilterListMetadata(t *testing.T, sequence uint64, now time.Time) ([]byte, []byte, []byte, PolicyFilterListTrustedKeys) {
	t.Helper()
	content := []byte("example.com\n")
	contentDigest := sha256.Sum256(content)
	metadata := PolicyFilterListSignedMetadata{
		Schema:        PolicyFilterListMetadataSchemaV1,
		SourceID:      "source-a",
		SourceURI:     "https://filters.example/list.txt",
		Publisher:     "GoreeCloud acceptance fixture",
		Sequence:      sequence,
		IssuedAt:      now.Add(-time.Minute).Format(time.RFC3339Nano),
		ExpiresAt:     now.Add(24 * time.Hour).Format(time.RFC3339Nano),
		ContentSHA256: hex.EncodeToString(contentDigest[:]),
		KeyID:         "primary",
	}
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	signature := ed25519.Sign(privateKey, metadataBytes)
	trusted := PolicyFilterListTrustedKeys{"primary": append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)}
	return metadataBytes, signature, content, trusted
}

func testFilterListPublicKey() ed25519.PublicKey {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	return append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
}
