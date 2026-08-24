#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
required = {
    "internal/gcdns/validating_stub_subdelegation.go": (
        "ValidatingDelegatingStubResolver",
        "NewValidatingDelegatingStubResolver",
        "resolveAnchoredApexKeys",
        "AuthenticateDNSKEYTrustAnchor",
        "AuthenticateDelegationDS",
        "AuthenticateDNSKEYResponse",
        "AuthenticateTerminalAnswer",
        "DNSSECInsecure",
        "DNSSECSecure",
        "lacks authenticated DS or denial proof",
        "validating stub delegation depth exceeded",
        "runtimeBoundary.validateTarget",
        "CheckingDisabled = req.Message.CheckingDisabled",
    ),
    "internal/gcdns/validating_stub_subdelegation_test.go": (
        "TestValidatingDelegatingStubResolverCarriesSecureChildTrust",
        "TestValidatingDelegatingStubResolverCarriesAuthenticatedInsecureChild",
        "TestValidatingDelegatingStubResolverRejectsUnprovenChildDelegation",
        "TestValidatingDelegatingStubResolverRejectsAnchorZoneMismatch",
    ),
    "internal/gcdns/validating_stub_subdelegation_hardening_test.go": (
        "TestRuntimeValidationRejectsValidatingStubRootSelfTarget",
        "TestRuntimeValidationAttachesBoundaryToValidatingStub",
        "TestValidatingDelegatingStubResolverRejectsQuestionOutsideZone",
        "TestValidatingDelegatingStubResolverRejectsBlankZone",
    ),
    "internal/gcdns/validating_stub_runtime_dynamic_test.go": (
        "TestValidatingStubRejectsDynamicChildSelfTarget",
    ),
    "internal/gcdns/stub_subdelegation.go": (
        "zone must not be blank",
        "maxStubDelegationDepth = 16",
        "completeReferralServers",
    ),
    "internal/gcdns/stub_constructor_blank_test.go": (
        "TestDelegatingStubResolverRejectsBlankZone",
    ),
    "internal/gcdns/routing_runtime_validation.go": (
        "ValidatingDelegatingStubResolver",
        "cloneResolverWithRuntimeBoundary",
        "nativeResolverTargetEndpoints",
    ),
    "docs/private-stub-dnssec.md": (
        "Secure child delegation",
        "Authenticated insecure child",
        "General Internet forwarding remains `DNSSECIndeterminate`",
        "dynamically discovered child targets are rejected",
        "Production boundary",
    ),
    "docs/routed-dnssec-policy.md": (
        "ValidatingDelegatingStubResolver",
        "child",
    ),
    "docs/resolver-routing.md": (
        "ValidatingDelegatingStubResolver",
        "child",
    ),
    "docs/iterative-dnssec-validation.md": (
        "ValidatingDelegatingStubResolver",
        "private",
    ),
    "docs/beacon.md": (
        "ValidatingDelegatingStubResolver",
        "private",
    ),
    ".github/workflows/lint.yml": (
        "validate_private_stub_dnssec.py",
    ),
}

for rel, markers in required.items():
    path = ROOT / rel
    if not path.is_file():
        raise SystemExit(f"Beacon private-stub DNSSEC validation failed: missing {rel}")
    text = path.read_text(encoding="utf-8")
    for marker in markers:
        if marker not in text:
            raise SystemExit(f"Beacon private-stub DNSSEC validation failed: {rel} missing {marker!r}")

print("GoreeCloud Beacon private stub DNSSEC trust-carry source contract: PASS")
