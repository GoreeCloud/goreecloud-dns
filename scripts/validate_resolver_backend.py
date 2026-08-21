#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "resolver" / "README.md"
CAPABILITIES = ROOT / "resolver" / "capabilities.json"
SUBSYSTEMS = ROOT / "resolver" / "subsystems.json"
CONFIG = ROOT / "resolver" / "config.example.json"
NATIVE_CORE = (
    ROOT / "internal" / "gcdns" / "contracts.go",
    ROOT / "internal" / "gcdns" / "pipeline.go",
    ROOT / "internal" / "gcdns" / "config.go",
    ROOT / "internal" / "gcdns" / "config_test.go",
    ROOT / "internal" / "gcdns" / "pipeline_test.go",
    ROOT / "internal" / "gcdns" / "cache.go",
    ROOT / "internal" / "gcdns" / "cache_test.go",
    ROOT / "internal" / "gcdns" / "cache_persistence.go",
    ROOT / "internal" / "gcdns" / "cache_persistence_test.go",
    ROOT / "internal" / "gcdns" / "cache_prefetch.go",
    ROOT / "internal" / "gcdns" / "cache_prefetch_test.go",
)

for path in (README, CAPABILITIES, SUBSYSTEMS, CONFIG, *NATIVE_CORE):
    if not path.is_file():
        raise SystemExit(f"resolver contract validation failed; missing {path.relative_to(ROOT)}")

contract = json.loads(CAPABILITIES.read_text(encoding="utf-8"))
subsystems = json.loads(SUBSYSTEMS.read_text(encoding="utf-8"))
config = json.loads(CONFIG.read_text(encoding="utf-8"))

if contract.get("schema_version") != 2:
    raise SystemExit("resolver contract validation failed; expected schema version 2")
if contract.get("product") != "GoreeCloud DNS":
    raise SystemExit("resolver contract validation failed; wrong product authority")
if contract.get("architecture") != "single-service":
    raise SystemExit("resolver contract validation failed; architecture must be single-service")
if contract.get("runtime_authority") != "GoreeCloud/goreecloud-dns":
    raise SystemExit("resolver contract validation failed; runtime authority must be GoreeCloud DNS")
if contract.get("external_recursive_resolver_required") is not False:
    raise SystemExit("resolver contract validation failed; external recursive resolver must not be required")
if set(contract.get("target_replaces", [])) != {"AdGuard Home", "Unbound"}:
    raise SystemExit("resolver contract validation failed; target must replace AdGuard Home and Unbound")
if set(contract.get("architecture_contracts", [])) != {"resolver/subsystems.json", "resolver/config.example.json"}:
    raise SystemExit("resolver contract validation failed; architecture contract references are incomplete")
if contract.get("production_approved") is not False:
    raise SystemExit("resolver contract validation failed; source contract cannot self-approve production")
if contract.get("runtime_acceptance_required") is not True:
    raise SystemExit("resolver contract validation failed; runtime acceptance must remain required")

required = set(contract.get("capabilities", []))
for capability in (
    "recursive-resolution", "authoritative-dns", "dnssec-validation", "dnssec-signing",
    "dns-cache", "persistent-cache", "serve-stale", "prefetch", "auto-prefetch",
    "dns-over-https", "dns-over-tls", "dns-over-quic", "integrated-dhcp", "clustering",
    "role-based-access-control", "oidc-single-sign-on", "metrics",
    "extensible-processing-framework",
):
    if capability not in required:
        raise SystemExit(f"resolver contract validation failed; missing capability: {capability}")

subsystem_ids = {item.get("id") for item in subsystems.get("subsystems", [])}
for subsystem in (
    "listener", "identity-policy", "query-pipeline", "filtering", "authoritative",
    "cache", "resolver", "dhcp", "cluster", "administration", "observability",
    "configuration", "security-runtime", "extensions",
):
    if subsystem not in subsystem_ids:
        raise SystemExit(f"resolver contract validation failed; missing subsystem: {subsystem}")

if config.get("production_approved") is not False:
    raise SystemExit("resolver contract validation failed; example configuration cannot self-approve production")
if config.get("security", {}).get("public_recursive_resolver") is not False:
    raise SystemExit("resolver contract validation failed; example config must not enable a public recursive resolver")
if set(config.get("security", {}).get("allow_recursion_from", [])) != {"127.0.0.0/8", "::1/128"}:
    raise SystemExit("resolver contract validation failed; example recursion ACL must remain loopback-only")
for listener_name in ("doh", "dot", "doq"):
    if config.get("listeners", {}).get(listener_name, {}).get("enabled") is not False:
        raise SystemExit(f"resolver contract validation failed; {listener_name} must be disabled by default")
if config.get("authoritative", {}).get("enabled") is not False:
    raise SystemExit("resolver contract validation failed; authoritative serving must be disabled by default")
if config.get("dhcp", {}).get("enabled") is not False:
    raise SystemExit("resolver contract validation failed; DHCP must be disabled by default")
if config.get("cluster", {}).get("enabled") is not False:
    raise SystemExit("resolver contract validation failed; clustering must be disabled by default")
if config.get("extensions", {}).get("enabled") is not False:
    raise SystemExit("resolver contract validation failed; extensions must be disabled by default")
if config.get("resolver", {}).get("dnssec_validation") is not True:
    raise SystemExit("resolver contract validation failed; DNSSEC validation must default on")
if config.get("filtering", {}).get("rebinding_protection") is not True:
    raise SystemExit("resolver contract validation failed; rebinding protection must default on")

native_contracts = (ROOT / "internal" / "gcdns" / "contracts.go").read_text(encoding="utf-8")
for marker in (
    "type Policy interface",
    "type Authority interface",
    "type Cache interface",
    "type Resolver interface",
    "CacheTTL time.Duration",
):
    if marker not in native_contracts:
        raise SystemExit(f"resolver contract validation failed; native contracts missing marker: {marker}")

native_pipeline = (ROOT / "internal" / "gcdns" / "pipeline.go").read_text(encoding="utf-8")
for marker in (
    "p.Policy.Evaluate",
    "p.Authority.ResolveAuthoritative",
    "p.Cache.Get",
    "p.Resolver.Resolve",
    "p.Cache.Put",
    '"cache-store"',
):
    if marker not in native_pipeline:
        raise SystemExit(f"resolver contract validation failed; native pipeline missing stage: {marker}")

pipeline_tests = (ROOT / "internal" / "gcdns" / "pipeline_test.go").read_text(encoding="utf-8")
for marker in (
    "TestPipelinePolicyShortCircuit",
    "TestPipelineAuthoritativeShortCircuit",
    "TestPipelineCacheHit",
    "TestPipelineResolverStoresCacheableResult",
):
    if marker not in pipeline_tests:
        raise SystemExit(f"resolver contract validation failed; native pipeline test missing: {marker}")

native_cache = (ROOT / "internal" / "gcdns" / "cache.go").read_text(encoding="utf-8")
for marker in (
    "type MemoryCache struct",
    "type MemoryCacheConfig struct",
    "type CacheStats struct",
    "ServeStale bool",
    "NegativeEntries uint64",
    "cache shard count must be a power of two",
    "gate       sync.RWMutex",
    "func ageResultTTL",
    "func isNegativeResponse",
    "func cloneResult",
):
    if marker not in native_cache:
        raise SystemExit(f"resolver contract validation failed; native cache missing marker: {marker}")

cache_tests = (ROOT / "internal" / "gcdns" / "cache_test.go").read_text(encoding="utf-8")
for marker in (
    "TestMemoryCachePutGetAndCopyIsolation",
    "TestMemoryCacheAgesWireTTL",
    "TestMemoryCacheExpires",
    "TestMemoryCacheServeStale",
    "TestMemoryCacheNegativeEntryAccounting",
    "TestMemoryCachePartitionsClients",
    "TestMemoryCacheEvictsOldestEntryWithinShard",
    "TestMemoryCacheConcurrentAccess",
):
    if marker not in cache_tests:
        raise SystemExit(f"resolver contract validation failed; native cache test missing: {marker}")

persistence = (ROOT / "internal" / "gcdns" / "cache_persistence.go").read_text(encoding="utf-8")
for marker in (
    "persistentCacheVersion = 1",
    "func (c *MemoryCache) SavePersistent",
    "func (c *MemoryCache) LoadPersistent",
    "os.CreateTemp",
    "tmp.Chmod(0o600)",
    "os.Rename",
):
    if marker not in persistence:
        raise SystemExit(f"resolver contract validation failed; persistent cache missing marker: {marker}")

persistence_tests = (ROOT / "internal" / "gcdns" / "cache_persistence_test.go").read_text(encoding="utf-8")
for marker in (
    "TestMemoryCachePersistentRoundTrip",
    "TestMemoryCachePersistentSkipsExpired",
    "TestMemoryCachePersistentRejectsInvalidState",
):
    if marker not in persistence_tests:
        raise SystemExit(f"resolver contract validation failed; persistent cache test missing: {marker}")

prefetch = (ROOT / "internal" / "gcdns" / "cache_prefetch.go").read_text(encoding="utf-8")
for marker in (
    "type PrefetchConfig struct",
    "type PrefetchCandidate struct",
    "type PrefetchCache struct",
    "func NewPrefetchCache",
    "func (p *PrefetchCache) Candidates",
    "MinimumHits uint64",
    "RefreshWithin time.Duration",
):
    if marker not in prefetch:
        raise SystemExit(f"resolver contract validation failed; prefetch cache missing marker: {marker}")

prefetch_tests = (ROOT / "internal" / "gcdns" / "cache_prefetch_test.go").read_text(encoding="utf-8")
for marker in (
    "TestPrefetchCacheSelectsPopularExpiringEntry",
    "TestPrefetchCacheDoesNotSelectColdOrFreshEntry",
    "TestPrefetchCacheFlushClearsPopularity",
    "TestPrefetchCacheValidation",
):
    if marker not in prefetch_tests:
        raise SystemExit(f"resolver contract validation failed; prefetch cache test missing: {marker}")

readme = README.read_text(encoding="utf-8")
for marker in (
    "Native cache implementation",
    "cache_persistence.go",
    "cache_prefetch.go",
    "owner-only temporary file and atomic rename",
    "native resolver scheduler",
):
    if marker not in readme:
        raise SystemExit(f"resolver contract validation failed; cache documentation missing marker: {marker}")

unbound_dir = ROOT / "resolver" / "unbound"
if unbound_dir.exists() and any(unbound_dir.iterdir()):
    raise SystemExit("resolver contract validation failed; separate Unbound backend files are prohibited")

print("GoreeCloud DNS integrated first-party DNS platform source contract: PASS")
