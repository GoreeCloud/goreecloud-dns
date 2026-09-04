#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
required = {
    "internal/gcdns/dnssec_nsec3.go": (
        "const nsec3OptOutFlag uint8 = 1",
        "validateNSEC3DelegationSet",
        "hasDelegationNS",
        "closestEncloserNSEC3",
        "nextCloserName",
        "coveringNSEC3",
        "lacks required opt-out flag on next-closer coverage",
        "NSEC3 opt-out denial is not yet supported for this authenticated-denial path",
        "return DNSSECInsecure, nil",
    ),
    "internal/gcdns/dnssec_nsec3_test.go": (
        "TestAuthenticateInsecureDelegationNSEC3ExactOptOut",
        "TestAuthenticateInsecureDelegationNSEC3OptOutCoverage",
        "TestAuthenticateInsecureDelegationNSEC3OptOutRequiresReferralNS",
        "TestAuthenticateInsecureDelegationNSEC3OptOutRequiresFlag",
        "TestAuthenticateNSEC3OptOutFailsClosed",
        "TestValidateNSEC3SetRejectsUnknownFlags",
    ),
    "internal/gcdns/dnssec_chain.go": (
        "narrowly scoped RFC 5155 Opt-Out",
        "AuthenticateInsecureDelegationNSEC3",
    ),
    "internal/gcdns/dnssec_chain_test.go": (
        "TestAuthenticateDelegationDSAcceptsNSEC3OptOutInsecureProof",
        "TestAuthenticateDelegationDSNSEC3OptOutMissingReferralRemainsIndeterminate",
        "TestAuthenticateDelegationDSNSEC3OptOutFailsClosed",
    ),
    "docs/iterative-dnssec-validation.md": (
        "Scoped NSEC3 Opt-Out",
        "actual referral NS",
        "next-closer",
        "terminal NODATA and NXDOMAIN",
    ),
}

for rel, markers in required.items():
    path = ROOT / rel
    if not path.is_file():
        raise SystemExit(f"Beacon NSEC3 Opt-Out validation failed: missing {rel}")
    text = path.read_text(encoding="utf-8")
    for marker in markers:
        if marker not in text:
            raise SystemExit(f"Beacon NSEC3 Opt-Out validation failed: {rel} missing {marker!r}")

print("GoreeCloud Beacon scoped NSEC3 Opt-Out delegation source contract: PASS")
