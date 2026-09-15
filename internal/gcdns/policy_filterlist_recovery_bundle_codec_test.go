package gcdns

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPolicyFilterListRecoveryBundleCodecRoundTripCanonical(t *testing.T) {
	bundle := mustPolicyFilterListRecoveryCodecBundle(t)
	bundle.StateFingerprintSHA256 = strings.ToUpper(bundle.StateFingerprintSHA256)
	bundle.TrustedKeys.StateFingerprintSHA256 = strings.ToUpper(bundle.TrustedKeys.StateFingerprintSHA256)
	bundle.ManagedConfig.StateFingerprintSHA256 = strings.ToUpper(bundle.ManagedConfig.StateFingerprintSHA256)
	if len(bundle.ManagedConfig.Sources) != 2 {
		t.Fatalf("managed source count = %d, want 2", len(bundle.ManagedConfig.Sources))
	}
	bundle.ManagedConfig.Sources[0], bundle.ManagedConfig.Sources[1] = bundle.ManagedConfig.Sources[1], bundle.ManagedConfig.Sources[0]

	data, err := EncodePolicyFilterListRecoveryBundle(bundle)
	if err != nil {
		t.Fatalf("EncodePolicyFilterListRecoveryBundle(): %v", err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatal("encoded recovery bundle is not newline terminated")
	}
	decoded, err := DecodePolicyFilterListRecoveryBundle(data)
	if err != nil {
		t.Fatalf("DecodePolicyFilterListRecoveryBundle(): %v", err)
	}
	if decoded.StateFingerprintSHA256 != strings.ToLower(bundle.StateFingerprintSHA256) {
		t.Fatalf("bundle fingerprint = %q, want canonical lowercase", decoded.StateFingerprintSHA256)
	}
	if decoded.TrustedKeys.StateFingerprintSHA256 != strings.ToLower(bundle.TrustedKeys.StateFingerprintSHA256) {
		t.Fatalf("trusted-key fingerprint = %q, want canonical lowercase", decoded.TrustedKeys.StateFingerprintSHA256)
	}
	if decoded.ManagedConfig.StateFingerprintSHA256 != strings.ToLower(bundle.ManagedConfig.StateFingerprintSHA256) {
		t.Fatalf("managed-config fingerprint = %q, want canonical lowercase", decoded.ManagedConfig.StateFingerprintSHA256)
	}
	if decoded.ManagedConfig.Sources[0].ID != "core" || decoded.ManagedConfig.Sources[1].ID != "privacy" {
		t.Fatalf("managed sources are not canonical: %+v", decoded.ManagedConfig.Sources)
	}
}

func TestDecodePolicyFilterListRecoveryBundleRejectsUnknownField(t *testing.T) {
	bundle := mustPolicyFilterListRecoveryCodecBundle(t)
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	data = append(data[:len(data)-1], []byte(`,"unexpected":true}`)...)

	_, err = DecodePolicyFilterListRecoveryBundle(data)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown-field rejection, got %v", err)
	}
}

func TestDecodePolicyFilterListRecoveryBundleRejectsTrailingJSON(t *testing.T) {
	bundle := mustPolicyFilterListRecoveryCodecBundle(t)
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	data = append(data, []byte("\n{}\n")...)

	_, err = DecodePolicyFilterListRecoveryBundle(data)
	if err == nil || !strings.Contains(err.Error(), "trailing JSON data") {
		t.Fatalf("expected trailing-data rejection, got %v", err)
	}
}

func TestDecodePolicyFilterListRecoveryBundleRejectsOversizedArtifact(t *testing.T) {
	data := make([]byte, maxPolicyFilterListRecoveryBundleBytes+1)
	_, err := DecodePolicyFilterListRecoveryBundle(data)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size rejection, got %v", err)
	}
}

func TestDecodePolicyFilterListRecoveryBundleRejectsTamperedFingerprint(t *testing.T) {
	bundle := mustPolicyFilterListRecoveryCodecBundle(t)
	bundle.StateFingerprintSHA256 = strings.Repeat("0", 64)
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}

	_, err = DecodePolicyFilterListRecoveryBundle(data)
	if err == nil || !strings.Contains(err.Error(), "bundle state fingerprint mismatch") {
		t.Fatalf("expected bundle fingerprint rejection, got %v", err)
	}
}

func TestEncodePolicyFilterListRecoveryBundleRejectsInvalidBundle(t *testing.T) {
	bundle := mustPolicyFilterListRecoveryCodecBundle(t)
	bundle.Schema = "unsupported"
	_, err := EncodePolicyFilterListRecoveryBundle(bundle)
	if err == nil || !strings.Contains(err.Error(), "unsupported filter-list recovery bundle schema") {
		t.Fatalf("expected schema rejection, got %v", err)
	}
}

func mustPolicyFilterListRecoveryCodecBundle(t *testing.T) PolicyFilterListRecoveryBundle {
	t.Helper()
	now := time.Date(2026, time.September, 15, 13, 0, 0, 0, time.UTC)
	trustedState := BootstrapPolicyFilterListTrustedKeyState(now.Add(-2 * time.Hour))
	trusted, err := BuildPolicyFilterListTrustedKeyRecoveryPoint(trustedState, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("build trusted-key recovery: %v", err)
	}
	manager := mustManagedConfigRecoveryManager(t, []PolicyFilterListManagedSource{
		{ID: "privacy", ExpectedSourceID: "privacy-source", Enabled: true, Priority: 20, Source: &managedConfigRecoverySnapshotSource{}},
		{ID: "core", ExpectedSourceID: "core-source", Enabled: true, Required: true, Priority: 100, Source: &managedConfigRecoverySnapshotSource{}},
	})
	managed, err := BuildPolicyFilterListManagedConfigRecoveryPoint(manager, 7, now.Add(-30*time.Minute))
	if err != nil {
		t.Fatalf("build managed-config recovery: %v", err)
	}
	bundle, err := BuildPolicyFilterListRecoveryBundle(trusted, managed, now)
	if err != nil {
		t.Fatalf("build recovery bundle: %v", err)
	}
	return bundle
}
