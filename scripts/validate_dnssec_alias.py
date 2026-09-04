#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
required = {
    "internal/gcdns/alias.go": (
        "maxAliasTransitions",
        "unresolvedAliasTarget",
        "validateAliasAnswerShape",
        "CNAME at %s coexists with other data",
        "nextAliasTarget",
        "dnameSubstitution",
        "aliasFollowupRequest",
        "mergeAliasResult",
        "combineAliasDNSSEC",
        "alias loop detected",
    ),
    "internal/gcdns/dnssec_answer.go": (
        "authenticateSynthesizedDNAMECNAME",
        "RFC 6672 synthesized CNAME",
        "authenticatedNSECDNAMEConflict",
        "authenticatedNSEC3DNAMEConflict",
        "suppresses an applicable DNAME",
    ),
    "internal/gcdns/iterative.go": (
        "resolveSingle",
        "unresolvedAliasTarget",
        "aliasFollowupRequest",
        "mergeAliasResult",
    ),
    "internal/gcdns/iterative_dnssec.go": (
        "resolveSingle",
        "combineAliasDNSSEC",
        "alias chain ended without a determinate DNSSEC trust state",
        "mergeAliasResult",
    ),
    "internal/gcdns/alias_test.go": (
        "TestUnresolvedAliasTargetCNAMERequiresFollowup",
        "TestUnresolvedAliasTargetDNAMEChecksSynthesizedCNAME",
        "TestUnresolvedAliasTargetDetectsCNAMECycle",
        "TestUnresolvedAliasTargetRejectsCNAMECoexistingData",
        "TestAuthenticateTerminalAnswerSignedCNAME",
        "TestAuthenticateTerminalAnswerAcceptsSignedDNAMEWithUnsignedSynthesizedCNAME",
        "TestAuthenticateTerminalAnswerRejectsMismatchedDNAMECNAME",
        "TestAuthenticateTerminalAnswerRejectsSynthesizedCNAMETTLMismatch",
        "TestAuthenticateTerminalAnswerRejectsSignedSynthesizedCNAME",
        "TestAuthenticatedNSEC3DNAMEConflictDetectsApplicableDNAME",
        "TestMergeAliasResultZeroTTLDisablesCombinedCaching",
        "TestIterativeResolverChasesCNAME",
        "TestValidatingIterativeResolverChasesSecureCNAME",
    ),
    "docs/iterative-dnssec-validation.md": (
        "Signed CNAME and DNAME chains",
        "synthesized CNAME",
        "combined chain is only `DNSSECSecure` when all hops are secure",
        "DNAME",
    ),
    "docs/beacon.md": (
        "CNAME/DNAME alias chains",
        "synthesized CNAME",
        "alias cycles",
    ),
}

for rel, markers in required.items():
    path = ROOT / rel
    if not path.is_file():
        raise SystemExit(f"Beacon DNSSEC alias validation failed: missing {rel}")
    text = path.read_text(encoding="utf-8")
    for marker in markers:
        if marker not in text:
            raise SystemExit(f"Beacon DNSSEC alias validation failed: {rel} missing {marker!r}")

print("GoreeCloud Beacon DNSSEC CNAME/DNAME alias-chain source contract: PASS")
