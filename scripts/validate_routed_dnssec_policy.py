#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
required = {
    "internal/gcdns/dnssec_trust_anchor.go": (
        "AuthenticateDNSKEYTrustAnchor",
        "configured DNSKEY trust anchor",
        "is not present in the apex DNSKEY RRset",
        "ValidateRRSet",
        "sameDNSKEYRData",
        "DNSSECSecure",
        "DNSSECBogus",
    ),
    "internal/gcdns/routed_dnssec_policy.go": (
        "PrivateDNSKEYTrustAnchor",
        "PrivateTrustAnchorResolver",
        "NewPrivateTrustAnchorResolver",
        "zone must not be blank",
        "CheckingDisabled = true",
        "AuthenticatedData = false",
        "CheckingDisabled = req.Message.CheckingDisabled",
        "AuthenticateDNSKEYTrustAnchor",
        "AuthenticateTerminalAnswer",
        "DNSSECSecure",
        "copyRequestForLocalValidation",
    ),
    "internal/gcdns/routed_dnssec_policy_test.go": (
        "TestPrivateTrustAnchorResolverAuthenticatesApexAndTerminalAnswer",
        "TestPrivateTrustAnchorResolverIgnoresUpstreamADOnUnsignedAnswer",
        "TestAuthenticateDNSKEYTrustAnchorRequiresAnchorInApexRRSet",
        "TestAuthenticateDNSKEYTrustAnchorRequiresAnchorToSignApexRRSet",
        "TestPrivateTrustAnchorResolverRejectsQuestionOutsideZone",
        "TestPrivateTrustAnchorResolverRejectsInvalidAnchor",
    ),
    "internal/gcdns/routed_dnssec_policy_hardening_test.go": (
        "TestPrivateTrustAnchorResolverRestoresDownstreamCD",
        "TestRuntimeValidationSeesThroughPrivateTrustAnchorForwarder",
        "TestRuntimeValidationAttachesBoundaryThroughPrivateTrustAnchorStub",
        "TestAuthenticateDNSKEYTrustAnchorRejectsNonZoneKeyAnchor",
        "TestPrivateTrustAnchorResolverRejectsBlankZone",
    ),
    "internal/gcdns/routing_runtime_validation.go": (
        "cloneResolverWithRuntimeBoundary",
        "PrivateTrustAnchorResolver",
        "nativeResolverTargetEndpoints(value.resolver)",
    ),
    "docs/routed-dnssec-policy.md": (
        "Explicit private DNSKEY trust anchors",
        "forces `CD=1`",
        "restores the original client's CD value",
        "Private child-delegation trust carry",
        "ValidatingDelegatingStubResolver",
        "Ordinary forwarded Internet data remains `DNSSECIndeterminate`",
        "Production boundary",
    ),
    "docs/resolver-routing.md": (
        "PrivateTrustAnchorResolver",
        "ValidatingDelegatingStubResolver",
        "Raw forward, terminal-only stub, and ordinary delegating-stub transports return `DNSSECIndeterminate`",
        "ValidatingForwardingResolver",
    ),
    "docs/iterative-dnssec-validation.md": (
        "PrivateTrustAnchorResolver",
        "configured private signed zone",
        "Raw `ForwardingResolver`, terminal-only `StubResolver`, and ordinary `DelegatingStubResolver` clear AD and return `DNSSECIndeterminate`",
        "ValidatingForwardingResolver",
    ),
    "docs/beacon.md": (
        "Beacon Routed Private DNSSEC Trust Anchors",
        "PrivateTrustAnchorResolver",
        "ValidatingDelegatingStubResolver",
        "Raw forwarded and ordinary stub responses clear `AD` and remain `DNSSECIndeterminate`",
        "ValidatingForwardingResolver",
    ),
    ".github/workflows/lint.yml": (
        "validate_routed_dnssec_policy.py",
    ),
}

for rel, markers in required.items():
    path = ROOT / rel
    if not path.is_file():
        raise SystemExit(f"Beacon routed-DNSSEC validation failed: missing {rel}")
    text = path.read_text(encoding="utf-8")
    for marker in markers:
        if marker not in text:
            raise SystemExit(f"Beacon routed-DNSSEC validation failed: {rel} missing {marker!r}")

print("GoreeCloud Beacon routed DNSSEC policy source contract: PASS")
