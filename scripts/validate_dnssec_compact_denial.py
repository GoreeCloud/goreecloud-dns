#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
required = {
    "internal/gcdns/contracts.go": (
        "CompactAnswersOK bool",
        "CompactDenial   bool",
        "CompactDenialCO bool",
    ),
    "internal/gcdns/dnssec_compact_denial.go": (
        "func (v *DNSSECValidator) AuthenticateCompactDenial",
        "dns.TypeNXNAME",
        "nsecBitmapExactly",
        "nsec3BitmapExactly",
        "messageCompactAnswersOK",
        "compactDenialMessageMetadata",
        "prepareCompactDenialForClient",
        "stripCompactDenialDNSSEC",
        "stripOPT",
        "compactDenialQueryResponse",
        "dns.RcodeFormatError",
        "NXNAME response used NXDOMAIN without the RFC 9824 CO response flag",
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
        "TestIterativeResolverRejectsNXNAMEWithoutExchange",
    ),
    "internal/gcdns/dnssec_compact_denial_co_test.go": (
        "TestAuthenticateCompactDenialAcceptsSignaledNXDOMAIN",
        "TestAuthenticateCompactDenialRejectsNXDOMAINWithoutCO",
        "TestExchangeResolverSignalsCompactAnswersOK",
        "TestExchangeResolverDoesNotSignalCOWithoutCapability",
        "TestPrepareCompactDenialForDNSSECClientWithoutCO",
        "TestPrepareCompactDenialForCOClient",
        "TestPrepareCompactDenialForNonDOClient",
        "TestPrepareCompactDenialForClientWithoutEDNS",
        "TestCompactDenialMessageMetadata",
        "TestMemoryCachePreservesCompactDenialMetadata",
        "TestPipelineRestoresCachedCompactDenialPerClient",
    ),
    "internal/gcdns/dnssec_answer.go": (
        "AuthenticateCompactDenial",
        "AuthenticateNSECNODATA",
        "AuthenticateNSECNXDOMAIN",
    ),
    "internal/gcdns/iterative.go": (
        "compactDenialQueryResponse(req)",
        "req.CompactAnswersOK",
        "SetCo()",
    ),
    "internal/gcdns/iterative_dnssec.go": (
        "compactDenialQueryResponse(req)",
        "requestWithCompactAnswersOK",
        "res.CompactDenial = present",
        "res.CompactDenialCO = present && responseCO",
    ),
    "internal/gcdns/pipeline.go": (
        "prepareCompactDenialForClient(req, res)",
        "cache-store",
    ),
    "docs/iterative-dnssec-validation.md": (
        "RFC 9824 Compact Denial of Existence",
        "NXNAME",
        "NOERROR",
        "Empty Non-Terminal",
        "Compact Answers OK",
        "hop-by-hop",
        "CompactDenialCO",
    ),
    "docs/beacon.md": (
        "RFC 9824 Compact Denial of Existence",
        "NXNAME",
        "Compact Answers OK",
        "hop-by-hop",
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

print("GoreeCloud Beacon RFC 9824 NXNAME/CO compact-denial source contract: PASS")
