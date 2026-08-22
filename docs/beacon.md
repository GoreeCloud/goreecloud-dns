# GoreeCloud Beacon

GoreeCloud Beacon is the official feature umbrella for the first-party capabilities of GoreeCloud DNS.

GoreeCloud DNS remains the application and service name. Beacon is not a separate daemon, product, or deployment boundary.

## Native resolver transition

The first executable Beacon foundation lives in `internal/gcdns` and is intentionally isolated from the inherited AdGuard Home production request path.

The native pipeline is:

`Policy -> Authoritative DNS -> Cache -> Resolver`

The contracts are designed so first-party caching, recursive resolution, forwarding, authoritative DNS, DNSSEC validation, filtering, observability, encrypted DNS, DHCP, clustering, and administration can be introduced incrementally without recreating a permanent AdGuard Home/Unbound split.

## Beacon Cache

`internal/gcdns/cache.go` provides a sharded, concurrency-safe bounded in-memory DNS cache with TTL expiration and wire-TTL aging, negative-response accounting, optional bounded serve-stale behavior, defensive DNS message copies, client-aware cache partitioning, serialized whole-cache flushes, and privacy-safe runtime statistics.

## Beacon Resolver Scheduler

`internal/gcdns/scheduler.go` implements named resolver targets, bounded scheduler concurrency, per-attempt context deadlines, caller cancellation, deterministic failover, health-aware target ordering, latency-aware ordering, and privacy-safe target statistics. A failed target does not terminate resolution while another configured target remains available.

## Beacon Classic DNS Transport

`internal/gcdns/transport.go` adds the first native wire transport for classic DNS. It performs UDP exchanges with an explicit EDNS-compatible response-size ceiling, retries valid truncated UDP responses over TCP, propagates caller cancellation, applies per-exchange deadlines, and rejects malformed or mismatched responses before they reach resolver logic.

Response validation requires the DNS response bit, matching transaction ID, matching opcode, matching question count, and canonical-name/type/class equivalence for every echoed question. A TCP response that remains truncated is rejected. Transport statistics expose only operational counters for exchanges, UDP successes, TCP fallbacks, TCP successes, failures, and timeouts; they do not retain query names, client identifiers, or DNS payloads.

Deterministic source tests cover response validation, successful UDP exchange, UDP-to-TCP truncation fallback, and configuration/input validation. These tests are development evidence only until executed by CI or an approved validation environment.

## Security boundary

The native foundation currently enforces source-level invariants for:

- DNSSEC validation enabled;
- DNS rebinding protection enabled;
- explicit recursion ACLs;
- no unrestricted recursion unless public recursion is explicitly enabled;
- no unrestricted administrative ACL;
- DNSSEC `bogus` results rejected before cache insertion;
- bounded, sharded cache configuration with explicit stale-serving limits;
- bounded resolver scheduler concurrency and explicit per-attempt deadlines;
- classic DNS response identity/question validation and bounded UDP response sizing.

These checks are development controls, not production acceptance evidence.

## Production boundary

No production traffic is routed through `internal/gcdns` yet. Existing AdGuard Home and Unbound runtime behavior remains unchanged until the native path has executable parity, tests, security validation, migration procedures, rollback procedures, and explicit production acceptance.

## Next implementation sequence

1. **Implemented foundation:** Native sharded DNS cache with TTL aging, negative caching, serve-stale, statistics, bounded capacity, and deterministic tests.
2. **Implemented foundation:** Resolver target scheduler with cancellation, timeout, failover, health/latency-aware selection, bounded concurrency, statistics, and deterministic tests.
3. **Implemented foundation:** Classic DNS UDP/TCP transport with truncation fallback, response validation, deadlines/cancellation, bounded UDP sizing, statistics, and deterministic tests.
4. Iterative recursion and delegation walking.
5. DNSSEC trust-anchor, DS/DNSKEY, RRSIG, and authenticated-denial validation.
6. Forward, conditional, stub, and split-horizon routing.
7. Persistent cache, prefetch/auto-prefetch, encrypted DNS, authoritative DNS, filtering, DHCP, clustering, APIs, and administration.
8. Controlled production integration and replacement acceptance.
