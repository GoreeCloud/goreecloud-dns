#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
required = {
    "internal/gcdns/validating_forwarding.go": (
        "ValidatingForwardingResolver",
        "NewValidatingForwardingResolver",
        "newValidatingForwardingResolver",
        "rootAnchors",
        "maxForwardValidationLabels = 128",
        "CheckingDisabled",
        "AuthenticatedData = false",
        "AuthenticateDNSKEYResponse",
        "AuthenticateDelegationDS",
        "AuthenticateNonDelegationDS",
        "DNSSECInsecure",
        "forwardingSignerZone",
        "forwardingAliasLinkMessage",
        "DS is parent-side data",
    ),
    "internal/gcdns/dnssec_non_delegation.go": (
        "AuthenticateNonDelegationDS",
        "not a delegation point",
        "nsecHasType(record, dns.TypeNS)",
        "nsec3HasType(record, dns.TypeNS)",
        "DNSSECSecure",
        "DNSSECIndeterminate",
    ),
    "internal/gcdns/validating_forwarding_test.go": (
        "TestValidatingForwardingResolverAuthenticatesSecureAnswer",
        "TestValidatingForwardingResolverCarriesAuthenticatedInsecureDelegation",
        "TestValidatingForwardingResolverRejectsUnclassifiedIntermediateDSState",
        "TestValidatingForwardingResolverRejectsInvalidConstruction",
        "TestForwardingValidationCandidatesWalkRootOutward",
    ),
    "internal/gcdns/validating_forwarding_non_delegation_test.go": (
        "TestValidatingForwardingResolverAuthenticatesAcrossNonDelegationLabel",
    ),
    "internal/gcdns/validating_forwarding_ds_test.go": (
        "TestValidatingForwardingResolverValidatesClientDSWithParentKeys",
    ),
    "internal/gcdns/validating_forwarding_alias_test.go": (
        "TestValidatingForwardingResolverRequeriesAliasTarget",
    ),
    "internal/gcdns/validating_forwarding_ad_test.go": (
        "TestValidatingForwardingResolverIgnoresUpstreamADOnUnsignedSecureBranch",
    ),
    "internal/gcdns/validating_forwarding_runtime_test.go": (
        "TestRuntimeValidationRejectsValidatingForwarderSelfTarget",
    ),
    "internal/gcdns/routing_runtime_validation.go": (
        "ValidatingForwardingResolver",
        "nativeResolverTargetEndpoints(value.forwarder)",
    ),
    "docs/validating-forwarding.md": (
        "Beacon Locally Validating Forwarding",
        "upstream AD ignored",
        "Parent-side DS queries",
        "Authenticated insecure forwarding",
        "Non-delegation proof boundary",
        "Production boundary",
    ),
    "docs/resolver-routing.md": (
        "ValidatingForwardingResolver",
        "locally validating",
    ),
    "docs/iterative-dnssec-validation.md": (
        "ValidatingForwardingResolver",
        "forwarding",
    ),
    "docs/beacon.md": (
        "ValidatingForwardingResolver",
        "forwarding",
    ),
    ".github/workflows/lint.yml": (
        "validate_validating_forwarding.py",
    ),
}

for rel, markers in required.items():
    path = ROOT / rel
    if not path.is_file():
        raise SystemExit(f"Beacon validating-forwarding source contract failed: missing {rel}")
    text = path.read_text(encoding="utf-8")
    for marker in markers:
        if marker not in text:
            raise SystemExit(f"Beacon validating-forwarding source contract failed: {rel} missing {marker!r}")

print("GoreeCloud Beacon validating forwarding source contract: PASS")
