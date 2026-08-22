# GoreeCloud Beacon

GoreeCloud Beacon is the official feature umbrella for the first-party capabilities of GoreeCloud DNS.

GoreeCloud DNS remains the application and service name. Beacon is not a separate daemon, product, or deployment boundary.

## Native resolver transition

The first executable Beacon foundation lives in `internal/gcdns` and is intentionally isolated from the inherited AdGuard Home production request path.

The native pipeline is:

`Policy -> Authoritative DNS -> Cache -> Resolver`

The contracts are designed so first-party caching, recursive resolution, forwarding, authoritative DNS, DNSSEC validation, filtering, observability, encrypted DNS, DHCP, clustering, and administration can be introduced incrementally without recreating a permanent AdGuard Home/Unbound split.

## Competitive target

GoreeCloud DNS is intended to become a capability superset of Technitium DNS Server, Pi-hole, and AdGuard Home across useful DNS features, while exceeding them where practical in privacy-by-default behavior, security boundaries, operator control, recovery, GoreeCloud platform integration, and first-party ownership. `docs/competitive-superset-requirement.md` records this as a target and acceptance requirement rather than a current completion claim.

## Beacon Cache

`internal/gcdns/cache.go` provides a sharded, concurrency-safe bounded in-memory DNS cache with TTL expiration and wire-TTL aging, negative-response accounting, optional bounded serve-stale behavior, defensive DNS message copies, client-aware cache partitioning, serialized whole-cache flushes, and privacy-safe runtime statistics.

## Beacon Resolver Scheduler

`internal/gcdns/scheduler.go` implements named resolver targets, bounded scheduler concurrency, per-attempt context deadlines, caller cancellation, deterministic failover, health-aware target ordering, latency-aware ordering, and privacy-safe target statistics.

## Beacon Classic DNS Transport

`internal/gcdns/transport.go` provides native UDP DNS exchange with TCP retry after valid truncation, per-exchange deadlines, caller cancellation, defensive response validation, and privacy-safe transport counters.

## Beacon Iterative Resolver

`internal/gcdns/iterative.go` walks delegations from verified root/bootstrap endpoints, clears recursion-desired on authoritative queries, uses the scheduler for per-delegation failover, follows referrals, accepts only in-bailiwick glue in the current foundation, derives cache lifetimes, and stops on configured depth or repeated delegation state.

## Beacon DNSSEC

Beacon carries current root DS trust anchors, authenticates DS-to-DNSKEY transitions, validates DNSKEY RRsets and RRSIGs, and carries authenticated keys through secure iterative delegations. Positive terminal DNS responses are now grouped into RRsets and each RRset must validate with authenticated DNSKEY/RRSIG material before the result may receive `secure` status.

Negative responses and unsigned delegations remain `indeterminate` until authenticated NSEC/NSEC3 denial exists. Complete cross-zone CNAME/DNAME validation, wildcard proofs, algorithm policy, and trust-anchor rollover automation remain staged work.

## Security boundary

The native foundation currently enforces source-level invariants for DNSSEC validation, DNS rebinding protection, explicit recursion ACLs, prevention of accidental open recursion, restricted administration, rejection of bogus DNSSEC results before caching, bounded cache and resolver concurrency, defensive transport validation, delegation loop/depth limits, in-bailiwick glue handling, secure DNSSEC trust carry, and fail-closed positive terminal-answer validation.

These checks are development controls, not production acceptance evidence.

## Production boundary

No production traffic is routed through `internal/gcdns` yet. Existing AdGuard Home and Unbound runtime behavior remains unchanged until the native path has executable parity, tests, security validation, migration procedures, rollback procedures, and explicit production acceptance.

## Next implementation sequence

1. **Implemented foundation:** Native sharded DNS cache.
2. **Implemented foundation:** Resolver target scheduler.
3. **Implemented foundation:** Classic UDP/TCP DNS transport.
4. **Implemented foundation:** Iterative recursion and secure delegation walking.
5. **Implemented foundation:** DNSSEC root trust, DS/DNSKEY authentication, RRSIG primitives, trust carry, and positive terminal-answer validation.
6. NSEC/NSEC3 authenticated denial, wildcard proofs, and complete signed alias-chain validation.
7. Out-of-bailiwick nameserver discovery, QNAME minimization, forward/conditional/stub routing, and split-horizon routing.
8. Persistent cache, prefetch/auto-prefetch, encrypted DNS, authoritative DNS, DNSSEC signing, catalog zones, secure zone transfers, filtering, DHCP, clustering, APIs, identity, administration, observability, and extensions.
9. Competitive-superset parity validation against current Technitium DNS Server, Pi-hole, and AdGuard Home stable capabilities.
10. Controlled production integration and replacement acceptance.
