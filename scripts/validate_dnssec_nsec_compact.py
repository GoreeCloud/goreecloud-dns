#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
required = {
    "internal/gcdns/dnssec_nsec_compact.go": (
        "func (v *DNSSECValidator) AuthenticateNSECNXDOMAINCompact",
        "compactClosestEncloserNSEC",
        "exactNSEC",
        "coveringNSEC(qname",
        "coveringNSEC(wildcard",
        "authenticated DNSKEY zone apex",
        "NXDOMAIN contradicts authenticated existing name",
        "NXDOMAIN contradicts authenticated wildcard owner",
        "contains DNAME and requires substitution",
        "NXDOMAIN proof crosses ancestor delegation",
        "return DNSSECSecure, nil",
    ),
    "internal/gcdns/dnssec_nsec_compact_test.go": (
        "TestAuthenticateNSECNXDOMAINCompactUsesImplicitZoneEncloser",
        "TestAuthenticateTerminalAnswerUsesCompactNSECNXDOMAIN",
        "TestAuthenticateNSECNXDOMAINCompactRequiresAncestorProof",
        "TestAuthenticateNSECNXDOMAINCompactRejectsExistingWildcard",
        "TestAuthenticateNSECNXDOMAINCompactRejectsDNAMEEncloser",
        "TestAuthenticateNSECNXDOMAINCompactRejectsAncestorDelegation",
    ),
    "internal/gcdns/dnssec_answer.go": (
        "AuthenticateNSECNXDOMAINCompact",
        "AuthenticateNSEC3NXDOMAIN",
    ),
    "docs/iterative-dnssec-validation.md": (
        "Compact NSEC NXDOMAIN",
        "intermediate ancestors",
        "DNAME",
        "ancestor delegation",
    ),
}

for rel, markers in required.items():
    path = ROOT / rel
    if not path.is_file():
        raise SystemExit(f"Beacon compact NSEC validation failed: missing {rel}")
    text = path.read_text(encoding="utf-8")
    for marker in markers:
        if marker not in text:
            raise SystemExit(f"Beacon compact NSEC validation failed: {rel} missing {marker!r}")

print("GoreeCloud Beacon compact NSEC NXDOMAIN source contract: PASS")
