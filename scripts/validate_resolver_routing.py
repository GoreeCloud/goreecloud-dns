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
        "TestRoutingResolverUsesLongestSuffix",
        "TestRoutingResolverExplicitRecursiveOverride",
        "TestRoutingResolverSplitHorizonByClientID",
        "TestRoutingResolverSplitHorizonUsesLongestPrefix",
        "TestForwardingResolverFailoverAndRD",
        "TestStubResolverRequiresAuthoritativeTerminalResponse",
        "TestRoutingResolverReroutesAliasTarget",
        "TestRoutingResolverDetectsRouteLoop",
        "TestRoutingResolverRejectsAmbiguousRoutes",
        "TestForwardingResolverRejectsInvalidTarget",
        "TestMemoryCacheSeparatesSameClientAcrossAddresses",
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
        "Subdelegation walking below a stub zone is deliberately staged",
        "Network-endpoint self-forward detection",
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
