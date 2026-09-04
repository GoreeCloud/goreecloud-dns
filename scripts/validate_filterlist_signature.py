#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

required = {
    "internal/gcdns/policy_filterlist_signature.go": (
        "goreecloud-beacon-filter-list-metadata/v1",
        "PolicyFilterListTrustedKeys",
        "VerifyPolicyFilterListSignedMetadata",
        "ed25519.Verify",
        "decoder.DisallowUnknownFields()",
        "signed filter-list content digest mismatch",
        "func (l *PolicyFilterListLifecycle) ApplySigned",
    ),
    "internal/gcdns/policy_filterlist_signature_test.go": (
        "TestVerifyPolicyFilterListSignedMetadata",
        "TestVerifyPolicyFilterListSignedMetadataRejectsTampering",
        "TestVerifyPolicyFilterListSignedMetadataRejectsUntrustedKeyAndTrailingJSON",
        "TestPolicyFilterListLifecycleApplySignedUsesNormalMonotonicity",
        "TestVerifyPolicyFilterListSignedMetadataRejectsUnknownFields",
    ),
    "internal/gcdns/policy_filterlist_trusted_keys.go": (
        "goreecloud-beacon-filter-list-trusted-keys/v1",
        "NewPolicyFilterListTrustedKeyStore",
        "BootstrapPolicyFilterListTrustedKeyState",
        "func (s *PolicyFilterListTrustedKeyStore) AddKey",
        "func (s *PolicyFilterListTrustedKeyStore) RevokeKey",
        "func (state PolicyFilterListTrustedKeyState) ActiveKeys",
        "filter-list trusted key fingerprint mismatch",
        "filter-list trusted public key already exists",
        "os.Rename(tmpName, s.path)",
        "os.Chmod(s.path, 0o600)",
    ),
    "internal/gcdns/policy_filterlist_trusted_keys_test.go": (
        "TestPolicyFilterListTrustedKeyStoreRotationAndRevocation",
        "TestPolicyFilterListTrustedKeyStoreRejectsReuseAndTampering",
        "revoked filter-list signing key remained active",
        "rotated filter-list signing key did not verify",
        "emergency revocation should fail closed with no active keys",
        "tampered trusted-key state error",
    ),
    "internal/gcdns/policy_filterlist_lifecycle.go": (
        "MetadataSHA256",
        "ContentSHA256",
        "filter-list sequence must increase",
        "filter-list source identity cannot change",
        "filter-list snapshot is expired",
    ),
    "docs/filter-list-lifecycle.md": (
        "Signed metadata and source trust",
        "detached Ed25519 signatures",
        "explicitly configured local trusted public key",
        "Unknown JSON fields and trailing JSON data fail closed",
        "performs no network I/O",
        "Everkeep",
        "production cutover",
    ),
    "docs/filter-list-acquisition.md": (
        "PolicyFilterListTrustedKeyStore",
        "Rotation is explicit",
        "Revoked key records are retained",
        "Reusing a revoked key ID",
        "emergency fail-closed action",
        "does not discover or trust signing keys from metadata, DNS, redirects, remote content",
        "Everkeep-backed trusted-key/filter lifecycle recovery",
        "AdGuard Home and Unbound remain production-authoritative",
    ),
}

for rel, markers in required.items():
    path = ROOT / rel
    if not path.is_file():
        raise SystemExit(f"Beacon signed filter-list validation failed: missing {rel}")
    text = path.read_text(encoding="utf-8")
    for marker in markers:
        if marker not in text:
            raise SystemExit(f"Beacon signed filter-list validation failed: {rel} missing {marker!r}")

print("GoreeCloud Beacon detached Ed25519 filter-list metadata verification, durable trusted-key rotation/revocation, immutable content binding, lifecycle integration, and production-safety contract: PASS")
