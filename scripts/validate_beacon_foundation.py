#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
required = {
    "internal/gcdns/contracts.go": (
        "type DNSSECStatus string",
        "DNSSECBogus",
        "type Policy interface",
        "type Authority interface",
        "type Cache interface",
        "type Resolver interface",
    ),
    "internal/gcdns/pipeline.go": (
        "p.Policy.Evaluate",
        "p.Authority.ResolveAuthoritative",
        "p.Cache.Get",
        "p.Resolver.Resolve",
        "p.Cache.Put",
        "refusing bogus dnssec result",
    ),
    "internal/gcdns/config.go": (
        "DNSSECValidation",
        "RebindingProtection",
        "PublicRecursion",
        "RecursionACLs",
        "AdminACLs",
    ),
    "internal/gcdns/pipeline_test.go": (
        "TestPipelineCacheHitSkipsResolver",
        "TestPipelineStoresCacheableResolverResult",
        "TestPipelineRejectsBogusDNSSECBeforeCache",
        "TestPipelinePolicyShortCircuits",
    ),
    "internal/gcdns/config_test.go": (
        "TestSecurityConfigValid",
        "TestSecurityConfigRequiresDNSSEC",
        "TestSecurityConfigRejectsUnrestrictedRecursionByDefault",
        "TestSecurityConfigRejectsUnrestrictedAdministration",
    ),
    "docs/beacon.md": (
        "GoreeCloud Beacon",
        "internal/gcdns",
        "Existing AdGuard Home and Unbound runtime behavior remains unchanged",
    ),
}

for rel, markers in required.items():
    path = ROOT / rel
    if not path.is_file():
        raise SystemExit(f"Beacon foundation validation failed: missing {rel}")
    text = path.read_text(encoding="utf-8")
    for marker in markers:
        if marker not in text:
            raise SystemExit(f"Beacon foundation validation failed: {rel} missing {marker!r}")

print("GoreeCloud Beacon native foundation source contract: PASS")
