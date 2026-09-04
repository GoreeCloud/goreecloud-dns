#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
required = {
    "internal/gcdns/qname_minimisation.go": (
        "qnameMinimisationQType",
        "dns.TypeA",
        "maxQNAMEMinimisationQueries",
        "10",
        "nextMinimisedQNAME",
        "qnameMinimisationProbe",
        "consumeQNAMEMinimisationBudget",
        "qnameMinimisationResponseHasDNAME",
        "TypeDS",
    ),
    "internal/gcdns/referral_discovery.go": (
        "qnameMinimisationQueries",
        "resolutionState",
    ),
    "internal/gcdns/iterative.go": (
        "qnameMinimisationEligible",
        "nextMinimisedQNAME",
        "consumeQNAMEMinimisationBudget",
        "Relaxed compatibility fallback",
        "does not yet use RFC 8020 NXDOMAIN cuts",
    ),
    "internal/gcdns/iterative_dnssec.go": (
        "qnameMinimisationEligible",
        "QNAME minimisation DNSSEC authentication failed",
        "unproven minimisation responses",
        "advanceValidatingReferral",
        "does not yet apply RFC 8020 cuts",
    ),
    "internal/gcdns/qname_minimisation_test.go": (
        "TestNextMinimisedQNAME",
        "TestQNAMEMinimisationBudgetIsBounded",
        "TestQNAMEMinimisationExcludesParentSideDS",
        "TestIterativeResolverMinimisesColdReferralWalk",
        "TestIterativeResolverFallsBackAfterMinimisationBudget",
        "TestValidatingIterativeResolverMinimisesSecureResponses",
        "TestValidatingIterativeResolverFallsBackOnIndeterminateProbe",
    ),
    "docs/qname-minimisation.md": (
        "RFC 9156",
        "fixed A",
        "10",
        "RFC 8020",
        "DNSSEC",
    ),
    "docs/beacon.md": (
        "QNAME minimisation",
        "RFC 9156",
    ),
    "docs/iterative-dnssec-validation.md": (
        "QNAME minimisation",
        "non-referral minimisation response must authenticate",
    ),
    ".github/workflows/lint.yml": (
        "validate_qname_minimisation.py",
    ),
}

for rel, markers in required.items():
    path = ROOT / rel
    if not path.is_file():
        raise SystemExit(f"Beacon QNAME minimisation validation failed: missing {rel}")
    text = path.read_text(encoding="utf-8")
    for marker in markers:
        if marker not in text:
            raise SystemExit(f"Beacon QNAME minimisation validation failed: {rel} missing {marker!r}")

print("GoreeCloud Beacon RFC 9156 QNAME minimisation source contract: PASS")
