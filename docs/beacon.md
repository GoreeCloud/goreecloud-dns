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

`internal/gcdns/transport.go` provides native classic DNS wire transport. It performs UDP exchanges with an explicit response-size ceiling, retries valid truncated UDP responses over TCP, propagates caller cancellation, applies per-exchange deadlines, and rejects malformed or mismatched responses before they reach resolver logic.

Response validation requires the DNS response bit, matching transaction ID, matching opcode, matching question count, and canonical-name/type/class equivalence for every echoed question. A TCP response that remains truncated is rejected. Transport statistics expose only operational counters; they do not retain query names, client identifiers, or DNS payloads.

## Beacon Iterative Resolver

`internal/gcdns/iterative.go` adds the first native delegation walker. It starts from an approved root/bootstrap endpoint set, clears the recursion-desired bit on authoritative queries, uses the Beacon TargetScheduler for per-delegation failover, sends queries through the DNSExchanger/ClassicTransport boundary, follows NS referrals, derives cache lifetimes from terminal responses, and stops on configured delegation depth or repeated delegation state.

`internal/gcdns/root_hints.go` contains the built-in IPv4 and IPv6 root bootstrap endpoints. The addresses were verified against the IANA Root Servers registry on 2026-08-22, including the current B-root addresses `170.247.170.2` and `2801:1b8:10::b`.

Referral processing is deliberately conservative. A glue address is accepted only when it corresponds to an NS name advertised by the referral and that NS name is inside the delegated zone. Out-of-bailiwick Additional-section addresses are ignored. If a referral has no usable in-bailiwick glue, the current foundation fails closed because recursive discovery of out-of-bailiwick NS addresses has not been implemented yet.

Terminal positive answers and authoritative negative responses return to the native pipeline with derived cache TTLs. Negative SOA lifetimes use the lower of SOA TTL and SOA MINIMUM. CNAME/DNAME chasing, out-of-bailiwick NS address discovery, QNAME minimization, lame-delegation handling, EDNS policy, richer retry policy, and DNSSEC trust validation remain future resolver stages.

Deterministic source tests cover referral walking, in-bailiwick IPv4/IPv6 glue, out-of-bailiwick rejection, delegation-loop detection, negative SOA cache lifetime derivation, current B-root bootstrap addresses, and configuration validation. These tests are development evidence only until executed by CI or an approved validation environment.

## Security boundary

The native foundation currently enforces source-level invariants for:

- DNSSEC validation enabled in the native security configuration;
- DNS rebinding protection enabled;
- explicit recursion ACLs;
- no unrestricted recursion unless public recursion is explicitly enabled;
- no unrestricted administrative ACL;
- DNSSEC `bogus` results rejected before cache insertion;
- bounded, sharded cache configuration with explicit stale-serving limits;
- bounded resolver scheduler concurrency and explicit per-attempt deadlines;
- classic DNS response identity/question validation and bounded UDP response sizing;
- iterative delegation depth limits and delegation-loop rejection;
- in-bailiwick-only glue acceptance in the initial referral implementation.

These checks are development controls, not production acceptance evidence.

## Production boundary

No production traffic is routed through `internal/gcdns` yet. Existing AdGuard Home and Unbound runtime behavior remains unchanged until the native path has executable parity, tests, security validation, migration procedures, rollback procedures, and explicit production acceptance.

## Next implementation sequence

1. **Implemented foundation:** Native sharded DNS cache with TTL aging, negative caching, serve-stale, statistics, bounded capacity, and deterministic tests.
2. **Implemented foundation:** Resolver target scheduler with cancellation, timeout, failover, health/latency-aware selection, bounded concurrency, statistics, and deterministic tests.
3. **Implemented foundation:** Classic DNS UDP/TCP transport with truncation fallback, response validation, deadlines/cancellation, bounded UDP sizing, statistics, and deterministic tests.
4. **Implemented foundation:** Iterative referral walking with verified root bootstrap targets, scheduler/transport integration, in-bailiwick glue, loop/depth protection, cache-TTL derivation, and deterministic tests.
5. DNSSEC trust-anchor, DS/DNSKEY, RRSIG, and authenticated-denial validation.
6. Out-of-bailiwick NS discovery, CNAME/DNAME chasing, QNAME minimization, forward/conditional/stub routing, and split-horizon routing.
7. Persistent cache, prefetch/auto-prefetch, encrypted DNS, authoritative DNS, filtering, DHCP, clustering, APIs, and administration.
8. Controlled production integration and replacement acceptance.
