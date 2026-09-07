package gcdns

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

func TestPolicyFilterListTrustedKeyRecoveryPointCanonicalizesState(t *testing.T) {
	now := time.Date(2026, 9, 7, 17, 50, 0, 0, time.UTC)
	state := PolicyFilterListTrustedKeyState{
		Schema:    PolicyFilterListTrustedKeyStateSchemaV1,
		UpdatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano),
		Keys: []PolicyFilterListTrustedKeyRecord{
			policyFilterListRecoveryTestRecord("z-key", 2, now.Add(-3*time.Hour), "manual"),
			policyFilterListRecoveryTestRecord("a-key", 1, now.Add(-2*time.Hour), "manual"),
		},
	}

	recovery, err := BuildPolicyFilterListTrustedKeyRecoveryPoint(state, now)
	if err != nil {
		t.Fatalf("build recovery point: %v", err)
	}
	if got, want := recovery.State.Keys[0].KeyID, "a-key"; got != want {
		t.Fatalf("first canonical key = %q, want %q", got, want)
	}
	if got, want := recovery.State.Keys[1].KeyID, "z-key"; got != want {
		t.Fatalf("second canonical key = %q, want %q", got, want)
	}

	reversed := state
	reversed.Keys = append([]PolicyFilterListTrustedKeyRecord(nil), state.Keys...)
	reversed.Keys[0], reversed.Keys[1] = reversed.Keys[1], reversed.Keys[0]
	other, err := BuildPolicyFilterListTrustedKeyRecoveryPoint(reversed, now)
	if err != nil {
		t.Fatalf("build reordered recovery point: %v", err)
	}
	if recovery.StateFingerprintSHA256 != other.StateFingerprintSHA256 {
		t.Fatalf("fingerprint changed with key ordering: %q != %q", recovery.StateFingerprintSHA256, other.StateFingerprintSHA256)
	}
}

func TestStagePolicyFilterListTrustedKeyRecoveryPointFromEmptyState(t *testing.T) {
	now := time.Date(2026, 9, 7, 18, 0, 0, 0, time.UTC)
	current := BootstrapPolicyFilterListTrustedKeyState(now.Add(-2 * time.Hour))
	recoveredState := PolicyFilterListTrustedKeyState{
		Schema:    PolicyFilterListTrustedKeyStateSchemaV1,
		UpdatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano),
		Keys: []PolicyFilterListTrustedKeyRecord{
			policyFilterListRecoveryTestRecord("primary", 3, now.Add(-3*time.Hour), "bootstrap"),
		},
	}
	recovery, err := BuildPolicyFilterListTrustedKeyRecoveryPoint(recoveredState, now)
	if err != nil {
		t.Fatalf("build recovery point: %v", err)
	}

	candidate, err := StagePolicyFilterListTrustedKeyRecoveryPoint(current, recovery, recovery.StateFingerprintSHA256)
	if err != nil {
		t.Fatalf("stage recovery point: %v", err)
	}
	if len(candidate.Keys) != 1 || candidate.Keys[0].KeyID != "primary" {
		t.Fatalf("unexpected candidate keys: %#v", candidate.Keys)
	}
	if len(current.Keys) != 0 {
		t.Fatalf("current state mutated: %#v", current.Keys)
	}
}

func TestStagePolicyFilterListTrustedKeyRecoveryPointRejectsEvidenceMismatch(t *testing.T) {
	now := time.Date(2026, 9, 7, 18, 10, 0, 0, time.UTC)
	state := PolicyFilterListTrustedKeyState{
		Schema:    PolicyFilterListTrustedKeyStateSchemaV1,
		UpdatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano),
		Keys: []PolicyFilterListTrustedKeyRecord{
			policyFilterListRecoveryTestRecord("primary", 4, now.Add(-2*time.Hour), "manual"),
		},
	}
	recovery, err := BuildPolicyFilterListTrustedKeyRecoveryPoint(state, now)
	if err != nil {
		t.Fatalf("build recovery point: %v", err)
	}

	wrong := bytes.Repeat([]byte{'0'}, 64)
	if _, err := StagePolicyFilterListTrustedKeyRecoveryPoint(state, recovery, string(wrong)); err == nil {
		t.Fatal("expected recovery evidence mismatch")
	}
}

func TestStagePolicyFilterListTrustedKeyRecoveryPointRejectsDroppedCurrentKey(t *testing.T) {
	now := time.Date(2026, 9, 7, 18, 20, 0, 0, time.UTC)
	current := PolicyFilterListTrustedKeyState{
		Schema:    PolicyFilterListTrustedKeyStateSchemaV1,
		UpdatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano),
		Keys: []PolicyFilterListTrustedKeyRecord{
			policyFilterListRecoveryTestRecord("current", 5, now.Add(-3*time.Hour), "manual"),
		},
	}
	older := BootstrapPolicyFilterListTrustedKeyState(now.Add(-2 * time.Hour))
	recovery, err := BuildPolicyFilterListTrustedKeyRecoveryPoint(older, now)
	if err != nil {
		t.Fatalf("build recovery point: %v", err)
	}

	if _, err := StagePolicyFilterListTrustedKeyRecoveryPoint(current, recovery, recovery.StateFingerprintSHA256); err == nil {
		t.Fatal("expected dropped-current-key rejection")
	}
}

func TestStagePolicyFilterListTrustedKeyRecoveryPointRejectsOlderState(t *testing.T) {
	now := time.Date(2026, 9, 7, 18, 25, 0, 0, time.UTC)
	record := policyFilterListRecoveryTestRecord("primary", 9, now.Add(-4*time.Hour), "manual")
	current := PolicyFilterListTrustedKeyState{
		Schema:    PolicyFilterListTrustedKeyStateSchemaV1,
		UpdatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano),
		Keys:      []PolicyFilterListTrustedKeyRecord{record},
	}
	older := PolicyFilterListTrustedKeyState{
		Schema:    PolicyFilterListTrustedKeyStateSchemaV1,
		UpdatedAt: now.Add(-2 * time.Hour).Format(time.RFC3339Nano),
		Keys:      []PolicyFilterListTrustedKeyRecord{record},
	}
	recovery, err := BuildPolicyFilterListTrustedKeyRecoveryPoint(older, now)
	if err != nil {
		t.Fatalf("build recovery point: %v", err)
	}

	if _, err := StagePolicyFilterListTrustedKeyRecoveryPoint(current, recovery, recovery.StateFingerprintSHA256); err == nil {
		t.Fatal("expected older-state rejection")
	}
}

func TestStagePolicyFilterListTrustedKeyRecoveryPointRejectsUnrevocation(t *testing.T) {
	now := time.Date(2026, 9, 7, 18, 30, 0, 0, time.UTC)
	currentRecord := policyFilterListRecoveryTestRecord("revoked", 6, now.Add(-4*time.Hour), "manual")
	currentRecord.RevokedAt = now.Add(-2 * time.Hour).Format(time.RFC3339Nano)
	currentRecord.RevocationReason = "compromised"
	current := PolicyFilterListTrustedKeyState{
		Schema:    PolicyFilterListTrustedKeyStateSchemaV1,
		UpdatedAt: now.Add(-2 * time.Hour).Format(time.RFC3339Nano),
		Keys:      []PolicyFilterListTrustedKeyRecord{currentRecord},
	}

	recoveredRecord := currentRecord
	recoveredRecord.RevokedAt = ""
	recoveredRecord.RevocationReason = ""
	recoveredState := PolicyFilterListTrustedKeyState{
		Schema:    PolicyFilterListTrustedKeyStateSchemaV1,
		UpdatedAt: now.Add(-3 * time.Hour).Format(time.RFC3339Nano),
		Keys:      []PolicyFilterListTrustedKeyRecord{recoveredRecord},
	}
	recovery, err := BuildPolicyFilterListTrustedKeyRecoveryPoint(recoveredState, now)
	if err != nil {
		t.Fatalf("build recovery point: %v", err)
	}

	if _, err := StagePolicyFilterListTrustedKeyRecoveryPoint(current, recovery, recovery.StateFingerprintSHA256); err == nil {
		t.Fatal("expected unrevocation rejection")
	}
}

func TestStagePolicyFilterListTrustedKeyRecoveryPointAllowsNewRevocation(t *testing.T) {
	now := time.Date(2026, 9, 7, 18, 40, 0, 0, time.UTC)
	currentRecord := policyFilterListRecoveryTestRecord("primary", 7, now.Add(-4*time.Hour), "manual")
	current := PolicyFilterListTrustedKeyState{
		Schema:    PolicyFilterListTrustedKeyStateSchemaV1,
		UpdatedAt: now.Add(-3 * time.Hour).Format(time.RFC3339Nano),
		Keys:      []PolicyFilterListTrustedKeyRecord{currentRecord},
	}

	recoveredRecord := currentRecord
	recoveredRecord.RevokedAt = now.Add(-time.Hour).Format(time.RFC3339Nano)
	recoveredRecord.RevocationReason = "rotation complete"
	recoveredState := PolicyFilterListTrustedKeyState{
		Schema:    PolicyFilterListTrustedKeyStateSchemaV1,
		UpdatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano),
		Keys:      []PolicyFilterListTrustedKeyRecord{recoveredRecord},
	}
	recovery, err := BuildPolicyFilterListTrustedKeyRecoveryPoint(recoveredState, now)
	if err != nil {
		t.Fatalf("build recovery point: %v", err)
	}

	candidate, err := StagePolicyFilterListTrustedKeyRecoveryPoint(current, recovery, recovery.StateFingerprintSHA256)
	if err != nil {
		t.Fatalf("stage recovery point: %v", err)
	}
	if candidate.Keys[0].RevokedAt == "" {
		t.Fatal("expected candidate to preserve newer revocation")
	}
}

func TestPolicyFilterListTrustedKeyRecoveryPointRejectsTampering(t *testing.T) {
	now := time.Date(2026, 9, 7, 18, 50, 0, 0, time.UTC)
	state := PolicyFilterListTrustedKeyState{
		Schema:    PolicyFilterListTrustedKeyStateSchemaV1,
		UpdatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano),
		Keys: []PolicyFilterListTrustedKeyRecord{
			policyFilterListRecoveryTestRecord("primary", 8, now.Add(-2*time.Hour), "manual"),
		},
	}
	recovery, err := BuildPolicyFilterListTrustedKeyRecoveryPoint(state, now)
	if err != nil {
		t.Fatalf("build recovery point: %v", err)
	}
	recovery.State.Keys[0].Source = "tampered"
	if _, err := StagePolicyFilterListTrustedKeyRecoveryPoint(state, recovery, recovery.StateFingerprintSHA256); err == nil {
		t.Fatal("expected tampered recovery point rejection")
	}
}

func policyFilterListRecoveryTestRecord(id string, seed byte, addedAt time.Time, source string) PolicyFilterListTrustedKeyRecord {
	publicKey := ed25519.PublicKey(bytes.Repeat([]byte{seed}, ed25519.PublicKeySize))
	return PolicyFilterListTrustedKeyRecord{
		KeyID:             id,
		PublicKey:         base64.StdEncoding.EncodeToString(publicKey),
		FingerprintSHA256: policyFilterListTrustedKeyFingerprint(publicKey),
		AddedAt:           addedAt.UTC().Format(time.RFC3339Nano),
		Source:            source,
	}
}
