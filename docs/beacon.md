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

Terminal positive answers and authoritative negative responses return to the native pipeline with derived cache TTLs. Negative SOA lifetimes use the lower of SOA TTL and SOA MINIMUM. CNAME/DNAME chasing, out-of-bailiwick NS address discovery, QNAME minimization, lame-delegation handling, EDNS policy, richer retry policy, and complete DNSSEC trust-chain validation remain future resolver stages.

## Beacon DNSSEC Foundation

`internal/gcdns/dnssec.go` introduces the first native DNSSEC trust primitives. Beacon now carries the current root-zone DS trust-anchor set for KSK-2017 (key tag 20326) and KSK-2024 (key tag 38696), matching the IANA-published rollover set reviewed on 2026-08-22. The October 11, 2026 root KSK signing rollover is therefore represented in source without removing the still-active 2017 anchor prematurely.

The DNSSEC validator can authenticate DNSKEY material against a parent-validated DS RRset using supported SHA-1, SHA-256, or SHA-384 DS digests, and it can validate a uniform RRset against matching DNSKEY/RRSIG material with signature inception/expiration checks and cryptographic verification through `miekg/dns`.

Beacon does not classify a delegation as insecure merely because DS is absent. Missing DS remains `indeterminate` until authenticated denial through NSEC/NSEC3 is implemented. A supported DS/DNSKEY mismatch is `bogus`, and the existing pipeline already refuses `bogus` resolver results before cache insertion.

Iterative queries now explicitly request DNSSEC material by setting EDNS and the DO bit with a minimum 1232-byte UDP size while preserving a larger caller-supplied EDNS size. This makes DS, DNSKEY, and RRSIG data available to later trust-chain integration instead of assuming that authoritative servers will return it unrequested.

Deterministic source tests cover the published root trust-anchor set, KSK-2017-to-DS matching, DS mismatch rejection, missing-DS indeterminate state, RRset validation boundaries, and iterative DNSSEC query signaling. Full root DNSKEY authentication, parent-to-child trust-chain carry, NSEC/NSEC3 authenticated denial, wildcard proof validation, trust-anchor rollover automation, and end-to-end iterative integration remain staged work.

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
- in-bailiwick-only glue acceptance in the initial referral implementation;
- explicit DNSSEC trust states, root trust anchors, DS/DNSKEY checks, RRSIG verification primitives, and DO-bit signaling.

These checks are development controls, not production acceptance evidence.

## Production boundary

No production traffic is routed through `internal/gcdns` yet. Existing AdGuard Home and Unbound runtime behavior remains unchanged until the native path has executable parity, tests, security validation, migration procedures, rollback procedures, and explicit production acceptance.

## Next implementation sequence

1. **Implemented foundation:** Native sharded DNS cache with TTL aging, negative caching, serve-stale, statistics, bounded capacity, and deterministic tests.
2. **Implemented foundation:** Resolver target scheduler with cancellation, timeout, failover, health/latency-aware selection, bounded concurrency, statistics, and deterministic tests.
3. **Implemented foundation:** Classic DNS UDP/TCP transport with truncation fallback, response validation, deadlines/cancellation, bounded UDP sizing, statistics, and deterministic tests.
4. **Implemented foundation:** Iterative referral walking with verified root bootstrap targets, scheduler/transport integration, in-bailiwick glue, loop/depth protection, cache-TTL derivation, and deterministic tests.
5. **Implemented foundation:** DNSSEC root trust anchors, DS/DNSKEY matching, RRset/RRSIG verification primitives, explicit trust states, DO-bit signaling, and deterministic tests.
6. DNSSEC trust-chain carry across referrals plus NSEC/NSEC3 authenticated denial and wildcard proof validation.
7. Out-of-bailiwick NS discovery, CNAME/DNAME chasing, QNAME minimization, forward/conditional/stub routing, and split-horizon routing.
8. Persistent cache, prefetch/auto-prefetch, encrypted DNS, authoritative DNS, filtering, DHCP, clustering, APIs, and administration.
9. Controlled production integration and replacement acceptance.
