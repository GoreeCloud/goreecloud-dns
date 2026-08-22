# GoreeCloud Beacon

GoreeCloud Beacon is the official feature umbrella for the first-party capabilities of GoreeCloud DNS.

GoreeCloud DNS remains the application and service name. Beacon is not a separate daemon, product, or deployment boundary.

## Native resolver transition

The first executable Beacon foundation lives in `internal/gcdns` and is intentionally isolated from the inherited AdGuard Home production request path.

The native pipeline is:

`Policy -> Authoritative DNS -> Cache -> Resolver`

The contracts are designed so first-party caching, recursive resolution, forwarding, authoritative DNS, DNSSEC validation, filtering, observability, encrypted DNS, DHCP, clustering, and administration can be introduced incrementally without recreating a permanent AdGuard Home/Unbound split.

## Beacon Cache

`internal/gcdns/cache.go` is the first substantive GoreeCloud-owned runtime subsystem behind the native pipeline. It provides a sharded, concurrency-safe in-memory DNS cache with bounded per-shard capacity, TTL expiration and wire-TTL aging, negative-response accounting, optional bounded serve-stale behavior, defensive DNS message copies, client-aware cache partitioning, serialized whole-cache flushes, and privacy-safe runtime statistics.

The cache intentionally accepts only caller-supplied positive cache lifetimes. Resolver and authoritative layers remain responsible for deriving standards-compliant positive and negative TTLs before insertion. Serve-stale returns zero-TTL DNS records so downstream clients are not encouraged to extend stale data further.

Deterministic tests cover copy isolation, wire-TTL aging, expiration, stale serving, negative-entry accounting, client partitioning, eviction, concurrent access, and configuration validation. These tests are source-development evidence only until executed by CI or an approved validation environment.

## Security boundary

The native foundation currently enforces source-level invariants for:

- DNSSEC validation enabled;
- DNS rebinding protection enabled;
- explicit recursion ACLs;
- no unrestricted recursion unless public recursion is explicitly enabled;
- no unrestricted administrative ACL;
- DNSSEC `bogus` results rejected before cache insertion;
- bounded, sharded cache configuration with explicit stale-serving limits.

These checks are development controls, not production acceptance evidence.

## Production boundary

No production traffic is routed through `internal/gcdns` yet. Existing AdGuard Home and Unbound runtime behavior remains unchanged until the native path has executable parity, tests, security validation, migration procedures, rollback procedures, and explicit production acceptance.

## Next implementation sequence

1. **Implemented foundation:** Native sharded DNS cache with TTL aging, negative caching, serve-stale, statistics, bounded capacity, and deterministic tests.
2. Resolver target scheduler with cancellation, timeout, failover, and latency-aware selection.
3. UDP/TCP transport with truncation fallback and defensive response validation.
4. Iterative recursion and delegation walking.
5. DNSSEC trust-anchor, DS/DNSKEY, RRSIG, and authenticated-denial validation.
6. Forward, conditional, stub, and split-horizon routing.
7. Persistent cache, prefetch/auto-prefetch, encrypted DNS, authoritative DNS, filtering, DHCP, clustering, APIs, and administration.
8. Controlled production integration and replacement acceptance.
