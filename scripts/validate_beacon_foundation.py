#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
required = {
    "internal/gcdns/contracts.go": ("type DNSSECStatus string", "DNSSECIndeterminate", "DNSSECInsecure", "DNSSECSecure", "DNSSECBogus", "type Policy interface", "type Authority interface", "type Cache interface", "type Resolver interface"),
    "internal/gcdns/pipeline.go": ("p.Policy.Evaluate", "p.Authority.ResolveAuthoritative", "p.Cache.Get", "p.Resolver.Resolve", "p.Cache.Put", "refusing bogus dnssec result"),
    "internal/gcdns/config.go": ("DNSSECValidation", "RebindingProtection", "PublicRecursion", "RecursionACLs", "AdminACLs"),
    "internal/gcdns/cache.go": ("type MemoryCacheConfig struct", "type MemoryCache struct", "cache shard count must be a positive power of two", "ServeStale bool", "NegativeEntries uint64", "func ageResultTTL", "func isNegativeResponse", "func cloneResult", "func (c *MemoryCache) Stats"),
    "internal/gcdns/cache_test.go": ("TestMemoryCachePutGetAndCopyIsolation", "TestMemoryCacheAgesWireTTL", "TestMemoryCacheExpires", "TestMemoryCacheServeStale", "TestMemoryCacheNegativeEntryAccounting", "TestMemoryCachePartitionsClients", "TestMemoryCacheEvictsWithinBound", "TestMemoryCacheConcurrentAccess", "TestMemoryCacheValidation"),
    "internal/gcdns/scheduler.go": ("type ResolverTarget struct", "type TargetScheduler struct", "AttemptTimeout time.Duration", "MaxConcurrent  int", "context.WithTimeout", "func (s *TargetScheduler) orderedTargets", "func (s *TargetScheduler) Stats", "var _ Resolver = (*TargetScheduler)(nil)"),
    "internal/gcdns/scheduler_test.go": ("TestTargetSchedulerFailsOver", "TestTargetSchedulerHonorsAttemptTimeout", "TestTargetSchedulerPrefersSuccessfulTarget", "TestTargetSchedulerPropagatesCallerCancellation", "TestTargetSchedulerValidatesConfiguration"),
    "internal/gcdns/transport.go": ("type ClassicTransportConfig struct", "type ClassicTransport struct", "UDPSize: cfg.MaxResponseSize", "if !udpReply.Truncated", "t.tcpFallbacks.Add(1)", "validateDNSReply", "DNS response ID mismatch", "DNS response question mismatch", "func (t *ClassicTransport) Stats"),
    "internal/gcdns/transport_test.go": ("TestValidateDNSReply", "TestClassicTransportUDP", "TestClassicTransportTCPFallback", "TestClassicTransportValidation"),
    "internal/gcdns/root_hints.go": ("func DefaultRootServers", "170.247.170.2:53", "[2801:1b8:10::b]:53", "202.12.27.33:53"),
    "internal/gcdns/iterative.go": ("type DNSExchanger interface", "type IterativeResolver struct", "RecursionDesired = false", "requestDNSSECMaterial", "referralTargets", "dns.IsSubDomain(zone, name)", "delegation loop detected", "responseCacheTTL", "var _ Resolver = (*IterativeResolver)(nil)"),
    "internal/gcdns/iterative_test.go": ("TestIterativeResolverFollowsReferral", "TestReferralTargetsAcceptInBailiwickGlue", "TestReferralTargetsRejectOutOfBailiwickGlue", "TestIterativeResolverDetectsDelegationLoop", "TestResponseCacheTTLNegativeSOA", "TestDefaultRootServersContainCurrentBRoot", "TestIterativeResolverValidation"),
    "internal/gcdns/dnssec.go": ("func RootTrustAnchors", "20326", "38696", "type DNSSECValidator struct", "func (v *DNSSECValidator) MatchDS", "key.ToDS", "func (v *DNSSECValidator) ValidateRRSet", "sig.Verify", "DNSSECSecure", "DNSSECBogus"),
    "internal/gcdns/dnssec_chain.go": ("func (v *DNSSECValidator) TrustedKeysForDS", "func (v *DNSSECValidator) AuthenticateDNSKEYResponse", "func (v *DNSSECValidator) AuthenticateDelegationDS", "DNSKEY RRset", "missing RRSIG", "DNSSECIndeterminate"),
    "internal/gcdns/dnssec_chain_test.go": ("TestTrustedKeysForDSReturnsOnlyAuthenticatedKeys", "TestTrustedKeysForDSRejectsMismatch", "TestAuthenticateDNSKEYResponseRequiresSignedRRSet", "TestAuthenticateDelegationDSRequiresParentSignature", "TestAuthenticateDelegationDSMissingDSRemainsIndeterminate", "TestDNSKEYMaterialFiltersZoneAndType"),
    "internal/gcdns/iterative_dnssec.go": ("type DNSSECChainAuthenticator interface", "type ValidatingIterativeResolver struct", "AuthenticateDNSKEYResponse", "AuthenticateDelegationDS", "root DNSSEC authentication failed", "cannot be classified secure without authenticated denial support", "DNSSECStatus = DNSSECIndeterminate", "var _ Resolver = (*ValidatingIterativeResolver)(nil)"),
    "internal/gcdns/iterative_dnssec_test.go": ("TestValidatingIterativeResolverCarriesSecureDelegationTrust", "TestValidatingIterativeResolverFailsClosedOnUnprovenDelegation", "TestValidatingIterativeResolverRequiresAuthenticator", "child server must not be queried after an unproven delegation"),
    "internal/gcdns/dnssec_test.go": ("TestRootTrustAnchors", "TestDNSSECValidatorMatchesRootKSK2017", "TestDNSSECValidatorRejectsDSMismatch", "TestDNSSECValidatorNoDSIsIndeterminate", "TestDNSSECValidatorRRSetWithoutMaterialIsIndeterminate", "TestDNSSECValidatorRejectsNonUniformRRSet"),
    "internal/gcdns/dnssec_query_test.go": ("TestRequestDNSSECMaterialAddsEDNSDO", "TestRequestDNSSECMaterialPreservesLargerUDPSize"),
    "internal/gcdns/pipeline_test.go": ("TestPipelineCacheHitSkipsResolver", "TestPipelineStoresCacheableResolverResult", "TestPipelineRejectsBogusDNSSECBeforeCache", "TestPipelinePolicyShortCircuits"),
    "internal/gcdns/config_test.go": ("TestSecurityConfigValid", "TestSecurityConfigRequiresDNSSEC", "TestSecurityConfigRejectsUnrestrictedRecursionByDefault", "TestSecurityConfigRejectsUnrestrictedAdministration"),
    "docs/beacon.md": ("GoreeCloud Beacon", "internal/gcdns", "Existing AdGuard Home and Unbound runtime behavior remains unchanged"),
}

for rel, markers in required.items():
    path = ROOT / rel
    if not path.is_file():
        raise SystemExit(f"Beacon foundation validation failed: missing {rel}")
    text = path.read_text(encoding="utf-8")
    for marker in markers:
        if marker not in text:
            raise SystemExit(f"Beacon foundation validation failed: {rel} missing {marker!r}")

print("GoreeCloud Beacon cache, scheduler, transport, iterative resolver, DNSSEC primitives, trust-chain helpers, and iterative trust carry source contract: PASS")
