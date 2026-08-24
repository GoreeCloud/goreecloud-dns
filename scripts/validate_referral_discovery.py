#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
required = {
    "internal/gcdns/referral_discovery.go": (
        "maxNameServerAddressLookups",
        "type referralPlan struct",
        "type resolutionState struct",
        "buildReferralPlan",
        "completeReferralServers",
        "discoverNameServerAddresses",
        "resolvedAddressEndpoints",
        "rrAddressEndpoint",
        "missing mandatory in-domain glue",
        "nameserver address discovery cycle",
        "nameserver address discovery work limit exceeded",
    ),
    "internal/gcdns/iterative.go": (
        "resolveWithState",
        "buildReferralPlan",
        "completeReferralServers",
        "r.resolveWithState",
    ),
    "internal/gcdns/iterative_dnssec.go": (
        "resolveWithState",
        "AuthenticateDelegationDS(plan.zone",
        "completeReferralServers",
        "r.resolveWithState",
        "resolveDNSKEY(ctx, plan.zone, nextServers)",
    ),
    "internal/gcdns/referral_discovery_test.go": (
        "TestBuildReferralPlanTracksOutOfBailiwickNameserver",
        "TestBuildReferralPlanRequiresInDomainGlue",
        "TestDiscoverNameServerAddressesCachesWithinResolution",
        "TestDiscoverNameServerAddressesRejectsActiveCycle",
        "TestDiscoverNameServerAddressesEnforcesWorkLimit",
        "TestResolvedAddressEndpointsFollowsAlias",
        "TestIterativeResolverDiscoversOutOfBailiwickNameserver",
        "TestValidatingIterativeResolverDiscoversOutOfBailiwickNameserver",
    ),
    "internal/gcdns/referral_discovery_hardening_test.go": (
        "TestBuildReferralPlanRejectsMalformedInDomainGlueAddress",
        "TestCompleteReferralServersContinuesAfterExternalLookupFailure",
        "TestResolvedAddressEndpointsRejectsMalformedAddress",
    ),
    "docs/out-of-bailiwick-nameserver-discovery.md": (
        "Out-of-Bailiwick Nameserver Discovery",
        "mandatory in-domain glue",
        "32 distinct external nameserver hostnames",
        "same resolver mode",
    ),
    "docs/beacon.md": (
        "out-of-bailiwick authoritative nameserver discovery",
        "request-scoped",
    ),
    "docs/iterative-dnssec-validation.md": (
        "out-of-bailiwick authoritative nameserver discovery",
        "request-scoped",
    ),
}

for rel, markers in required.items():
    path = ROOT / rel
    if not path.is_file():
        raise SystemExit(f"Beacon referral discovery validation failed: missing {rel}")
    text = path.read_text(encoding="utf-8")
    for marker in markers:
        if marker not in text:
            raise SystemExit(f"Beacon referral discovery validation failed: {rel} missing {marker!r}")

print("GoreeCloud Beacon out-of-bailiwick nameserver discovery source contract: PASS")
