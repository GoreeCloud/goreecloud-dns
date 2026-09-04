#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
required = {
    "internal/gcdns/dnssec_answer.go": (
        "authenticateTerminalPositiveRRSet",
        "AuthenticateWildcardExpansion",
        "AuthenticateWildcardNODATA",
        "literalWildcardOwner",
        "int(sig.Labels) == ownerLabels",
        "int(sig.Labels) >= ownerLabels",
        "wildcard expansion for",
    ),
    "internal/gcdns/dnssec_wildcard.go": (
        "func (v *DNSSECValidator) AuthenticateWildcardExpansion",
        "func (v *DNSSECValidator) AuthenticateWildcardNODATA",
        "func (v *DNSSECValidator) AuthenticateNSECWildcardAnswer",
        "func (v *DNSSECValidator) AuthenticateNSECWildcardNODATA",
        "func (v *DNSSECValidator) AuthenticateNSEC3WildcardAnswer",
        "func (v *DNSSECValidator) AuthenticateNSEC3WildcardNODATA",
        "wildcardClosestEncloser",
        "closestWildcardNSEC",
        "nextCloserName",
        "coveringNSEC",
        "coveringNSEC3",
        "invalid because closer name",
    ),
    "internal/gcdns/dnssec_wildcard_test.go": (
        "TestAuthenticateTerminalAnswerSignedDirectPositive",
        "TestAuthenticateTerminalAnswerLiteralWildcardOwner",
        "TestAuthenticateTerminalAnswerWildcardNSEC",
        "TestAuthenticateTerminalAnswerWildcardNSEC3",
        "TestAuthenticateTerminalAnswerWildcardMissingProofFailsClosed",
        "TestAuthenticateTerminalAnswerWildcardRejectsExistingCloserName",
        "TestAuthenticateTerminalAnswerWildcardNODATANSEC",
        "TestAuthenticateTerminalAnswerWildcardNODATANSECRejectsExistingType",
        "TestAuthenticateTerminalAnswerWildcardNODATANSEC3",
        "TestAuthenticateTerminalAnswerWildcardNODATANSEC3RejectsExistingType",
        "TestWildcardClosestEncloser",
    ),
    "docs/iterative-dnssec-validation.md": (
        "Wildcard-expanded positive answers",
        "Wildcard NODATA",
        "RRSIG Labels",
        "next-closer",
        "NSEC3",
    ),
}

for rel, markers in required.items():
    path = ROOT / rel
    if not path.is_file():
        raise SystemExit(f"Beacon wildcard validation failed: missing {rel}")
    text = path.read_text(encoding="utf-8")
    for marker in markers:
        if marker not in text:
            raise SystemExit(f"Beacon wildcard validation failed: {rel} missing {marker!r}")

print("GoreeCloud Beacon DNSSEC wildcard positive-answer and NODATA source contract: PASS")
