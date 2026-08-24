#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
required = {
    "internal/gcdns/dnssec_compact_denial.go": (
        "func (v *DNSSECValidator) AuthenticateCompactDenial",
        "dns.TypeNXNAME",
        "nsecBitmapExactly",
        "nsec3BitmapExactly",
        "compactDenialQueryResponse",
        "dns.RcodeFormatError",
        "compact denial mixes NSEC and NSEC3 NXNAME material",
        "not exactly RRSIG, NSEC, NXNAME",
        "not exactly NXNAME",
    ),
    "internal/gcdns/dnssec_compact_denial_test.go": (
        "TestAuthenticateCompactDenialNSEC",
        "TestAuthenticateCompactDenialNSECRejectsExtraType",
        "TestAuthenticateCompactDenialOrdinaryNODATANotHandled",
        "TestAuthenticateCompactDenialNSEC3",
        "TestAuthenticateCompactDenialNSEC3RejectsExtraType",
        "TestAuthenticateTerminalAnswerUsesCompactDenial",
        "TestCompactDenialNXNAMEQueryReturnsFORMERR",
    ),
    "internal/gcdns/dnssec_answer.go": (
        "AuthenticateCompactDenial",
        "AuthenticateNSECNODATA",
        "AuthenticateNSECNXDOMAIN",
    ),
    "internal/gcdns/iterative.go": (
        "compactDenialQueryResponse(req)",
    ),
    "internal/gcdns/iterative_dnssec.go": (
        "compactDenialQueryResponse(req)",
    ),
    "docs/iterative-dnssec-validation.md": (
        "RFC 9824 Compact Denial of Existence",
        "NXNAME",
        "NOERROR",
        "Empty Non-Terminal",
        "Compact Answers OK",
    ),
    "docs/beacon.md": (
        "RFC 9824 Compact Denial of Existence",
        "NXNAME",
        "NOERROR",
    ),
}

for rel, markers in required.items():
    path = ROOT / rel
    if not path.is_file():
        raise SystemExit(f"Beacon RFC 9824 compact-denial validation failed: missing {rel}")
    text = path.read_text(encoding="utf-8")
    for marker in markers:
        if marker not in text:
            raise SystemExit(f"Beacon RFC 9824 compact-denial validation failed: {rel} missing {marker!r}")

for obsolete in (
    "internal/gcdns/dnssec_nsec_compact.go",
    "internal/gcdns/dnssec_nsec_compact_test.go",
    "scripts/validate_dnssec_nsec_compact.py",
):
    if (ROOT / obsolete).exists():
        raise SystemExit(f"Beacon RFC 9824 compact-denial validation failed: obsolete unsafe source remains: {obsolete}")

print("GoreeCloud Beacon RFC 9824 NXNAME compact-denial source contract: PASS")
