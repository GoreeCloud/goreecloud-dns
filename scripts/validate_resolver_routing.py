#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
required = {
    "internal/gcdns/routing.go": (
        "RouteRecursive",
        "RouteForward",
        "RouteStub",
        "NewRoutingResolver",
        "selectRoute",
        "routeScore",
        "resolver route loop detected",
        "NewForwardingResolver",
        "RecursionDesired = true",
        "AuthenticatedData = false",
        "DNSSECIndeterminate",
        "NewStubResolver",
        "RecursionDesired = false",
        "terminal authoritative response",
        "validateDNSTarget",
    ),
    "internal/gcdns/routing_test.go": (
        "TestRoutingResolverUsesLongestNamespaceSuffix",
        "TestRoutingResolverFallsBackToRecursiveDefault",
        "TestRoutingResolverRecursiveRouteOverridesBroadForward",
        "TestRoutingResolverSplitHorizonClientIDOutranksPrefix",
        "TestRoutingResolverSplitHorizonUsesLongestClientPrefix",
        "TestForwardingResolverSetsRDAndFailsOver",
        "TestStubResolverClearsRDAndRequiresAuthoritativeTerminalResponse",
        "TestRoutingResolverChasesAliasAcrossRoutes",
        "TestRoutingResolverDetectsRouteLoop",
        "TestRoutingResolverRejectsAmbiguousAndInvalidConfiguration",
    ),
    "internal/gcdns/cache_routing_partition_test.go": (
        "TestMemoryCacheSeparatesSameClientAcrossAddresses",
    ),
    "internal/gcdns/routing_runtime_validation.go": (
        "NewRuntimeValidatedRoutingResolver",
        "routingRuntimeBoundary",
        "clone.runtimeBoundary = boundary",
        "ValidateRoutingRuntime",
        "routing runtime validation requires at least one active listener",
        "runtime self-target validation requires a numeric IP address",
        "resolver target address must not be unspecified",
        "points back to an active GoreeCloud DNS listener",
        "DelegatingStubResolver",
        "routingTargetHitsListener",
        "localAddresses",
    ),
    "internal/gcdns/routing_runtime_validation_test.go": (
        "TestNewRuntimeValidatedRoutingResolverRejectsSelfTarget",
        "TestNewRuntimeValidatedRoutingResolverAcceptsExternalTarget",
        "TestValidateRoutingRuntimeRejectsExactForwardSelfTarget",
        "TestValidateRoutingRuntimeRejectsWildcardLoopbackTarget",
        "TestValidateRoutingRuntimeRejectsWildcardKnownLocalAddress",
        "TestValidateRoutingRuntimeAllowsExternalTargetOnWildcardPort",
        "TestValidateRoutingRuntimeAllowsLocalAddressOnDifferentPort",
        "TestValidateRoutingRuntimeRejectsStubSelfTarget",
        "TestValidateRoutingRuntimeRejectsIPv6WildcardLoopbackTarget",
        "TestValidateRoutingRuntimeRequiresNumericTargetAddress",
        "TestValidateRoutingRuntimeRejectsInvalidLocalAddressSnapshot",
        "TestValidateRoutingRuntimeRequiresListener",
    ),
    "internal/gcdns/stub_subdelegation.go": (
        "maxStubDelegationDepth = 16",
        "DelegatingStubResolver",
        "NewDelegatingStubResolver",
        "runtimeBoundary *routingRuntimeBoundary",
        "stub referral",
        "is not closer than current authority",
        "resolveAddressWithinStub",
        "stub nameserver",
        "outside configured zone",
        "completeReferralServers",
        "runtimeBoundary.validateTarget",
        "AuthenticatedData = false",
        "DNSSECIndeterminate",
    ),
    "internal/gcdns/stub_subdelegation_test.go": (
        "TestDelegatingStubResolverFollowsInDomainGlueReferral",
        "TestDelegatingStubResolverResolvesSiblingNameserverInsideStubZone",
        "TestDelegatingStubResolverRejectsNameserverOutsideStubZone",
        "TestDelegatingStubResolverRejectsNonCloserReferral",
        "TestDelegatingStubResolverFailsOverNonAuthoritativeTerminalResponse",
        "TestDelegatingStubResolverClearsAuthenticatedData",
    ),
    "internal/gcdns/stub_subdelegation_hardening_test.go": (
        "TestDelegatingStubResolverEnforcesDelegationDepth",
        "TestValidateRoutingRuntimeRejectsDelegatingStubSelfTarget",
        "TestDelegatingStubResolverRejectsQuestionOutsideConfiguredZone",
        "TestDelegatingStubResolverRejectsInvalidConstruction",
    ),
    "internal/gcdns/stub_runtime_boundary_test.go": (
        "TestRuntimeValidatedRouterRejectsDiscoveredStubSelfTarget",
        "TestRuntimeValidatedRouterAllowsDiscoveredExternalStubTarget",
    ),
    "internal/gcdns/cache.go": (
        "id=%s|ip=%s",
        "split-horizon",
        "ClientID",
        "ClientIP",
    ),
    "docs/resolver-routing.md": (
        "longest DNS-suffix matching",
        "Split-horizon scope",
        "both `ClientID` and `ClientIP`",
        "DNSSECIndeterminate",
        "runtime self-target validation",
        "NewRuntimeValidatedRoutingResolver",
        "DelegatingStubResolver",
        "16 delegation transitions",
        "A nameserver hostname outside the configured stub namespace is not resolved through public Internet recursion",
        "Production boundary",
    ),
    "docs/beacon.md": (
        "Beacon Resolver Routing",
        "forward",
        "stub",
        "split-horizon",
    ),
    "docs/iterative-dnssec-validation.md": (
        "forwarded",
        "stub",
        "DNSSECIndeterminate",
    ),
    ".github/workflows/lint.yml": (
        "validate_resolver_routing.py",
    ),
}

for rel, markers in required.items():
    path = ROOT / rel
    if not path.is_file():
        raise SystemExit(f"Beacon resolver-routing validation failed: missing {rel}")
    text = path.read_text(encoding="utf-8")
    for marker in markers:
        if marker not in text:
            raise SystemExit(f"Beacon resolver-routing validation failed: {rel} missing {marker!r}")

print("GoreeCloud Beacon resolver-routing source contract: PASS")
