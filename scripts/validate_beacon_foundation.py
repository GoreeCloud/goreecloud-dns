#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
required = {
    "internal/gcdns/contracts.go": (
        "type DNSSECStatus string", "DNSSECBogus", "type Policy interface", "type Authority interface", "type Cache interface", "type Resolver interface",
    ),
    "internal/gcdns/pipeline.go": (
        "p.Policy.Evaluate", "p.Authority.ResolveAuthoritative", "p.Cache.Get", "p.Resolver.Resolve", "p.Cache.Put", "refusing bogus dnssec result",
    ),
    "internal/gcdns/config.go": (
        "DNSSECValidation", "RebindingProtection", "PublicRecursion", "RecursionACLs", "AdminACLs",
    ),
    "internal/gcdns/cache.go": (
        "type MemoryCacheConfig struct", "type MemoryCache struct", "cache shard count must be a positive power of two", "ServeStale bool", "NegativeEntries uint64", "func ageResultTTL", "func isNegativeResponse", "func cloneResult", "func (c *MemoryCache) Stats",
    ),
    "internal/gcdns/cache_test.go": (
        "TestMemoryCachePutGetAndCopyIsolation", "TestMemoryCacheAgesWireTTL", "TestMemoryCacheExpires", "TestMemoryCacheServeStale", "TestMemoryCacheNegativeEntryAccounting", "TestMemoryCachePartitionsClients", "TestMemoryCacheEvictsWithinBound", "TestMemoryCacheConcurrentAccess", "TestMemoryCacheValidation",
    ),
    "internal/gcdns/scheduler.go": (
        "type ResolverTarget struct", "type TargetScheduler struct", "AttemptTimeout time.Duration", "MaxConcurrent  int", "context.WithTimeout", "func (s *TargetScheduler) orderedTargets", "func (s *TargetScheduler) Stats", "var _ Resolver = (*TargetScheduler)(nil)",
    ),
    "internal/gcdns/scheduler_test.go": (
        "TestTargetSchedulerFailsOver", "TestTargetSchedulerHonorsAttemptTimeout", "TestTargetSchedulerPrefersSuccessfulTarget", "TestTargetSchedulerPropagatesCallerCancellation", "TestTargetSchedulerValidatesConfiguration",
    ),
    "internal/gcdns/pipeline_test.go": (
        "TestPipelineCacheHitSkipsResolver", "TestPipelineStoresCacheableResolverResult", "TestPipelineRejectsBogusDNSSECBeforeCache", "TestPipelinePolicyShortCircuits",
    ),
    "internal/gcdns/config_test.go": (
        "TestSecurityConfigValid", "TestSecurityConfigRequiresDNSSEC", "TestSecurityConfigRejectsUnrestrictedRecursionByDefault", "TestSecurityConfigRejectsUnrestrictedAdministration",
    ),
    "docs/beacon.md": (
        "GoreeCloud Beacon", "internal/gcdns", "Existing AdGuard Home and Unbound runtime behavior remains unchanged",
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

print("GoreeCloud Beacon native foundation, cache, and resolver scheduler source contract: PASS")
