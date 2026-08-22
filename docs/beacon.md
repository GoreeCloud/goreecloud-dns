# GoreeCloud Beacon

GoreeCloud Beacon is the official feature umbrella for the first-party capabilities of GoreeCloud DNS.

GoreeCloud DNS remains the application and service name. Beacon is not a separate daemon, product, or deployment boundary.

## Native resolver transition

The first executable Beacon foundation lives in `internal/gcdns` and is intentionally isolated from the inherited AdGuard Home production request path.

The native pipeline is:

`Policy -> Authoritative DNS -> Cache -> Resolver`

The contracts are designed so first-party caching, recursive resolution, forwarding, authoritative DNS, DNSSEC validation, filtering, observability, encrypted DNS, DHCP, clustering, and administration can be introduced incrementally without recreating a permanent AdGuard Home/Unbound split.

## Competitive direction

GoreeCloud DNS targets a stable capability superset of Technitium DNS Server, Pi-hole, and AdGuard Home in useful DNS features while aiming to exceed those references in privacy-by-default behavior, security boundaries, operator control, resilience, observability, recovery, GoreeCloud integration, and first-party ownership. This is a product requirement, not a claim that every target capability is already implemented.

## Beacon Cache

`internal/gcdns/cache.go` provides a sharded, concurrency-safe bounded in-memory DNS cache with TTL expiration and wire-TTL aging, negative-response accounting, optional bounded serve-stale behavior, defensive DNS message copies, client-aware cache partitioning, serialized whole-cache flushes, and privacy-safe runtime statistics.

## Beacon Resolver Scheduler

`internal/gcdns/scheduler.go` implements named resolver targets, bounded scheduler concurrency, per-attempt context deadlines, caller cancellation, deterministic failover, health-aware target ordering, latency-aware ordering, and privacy-safe target statistics.

## Beacon Classic DNS Transport

`internal/gcdns/transport.go` provides native classic DNS wire transport. It performs UDP exchanges with an explicit response-size ceiling, retries valid truncated UDP responses over TCP, propagates caller cancellation, applies per-exchange deadlines, and rejects malformed or mismatched responses before they reach resolver logic.

## Beacon Iterative Resolver

`internal/gcdns/iterative.go` provides the native delegation walker. It starts from an approved root/bootstrap endpoint set, clears the recursion-desired bit on authoritative queries, uses the Beacon scheduler for per-delegation failover, sends queries through the DNSExchanger/ClassicTransport boundary, follows NS referrals, derives cache lifetimes from terminal responses, and stops on configured delegation depth or repeated delegation state.

Referral processing remains conservative: only advertised in-bailiwick glue is accepted. Out-of-bailiwick nameserver address discovery remains a later resolver milestone.

## Beacon DNSSEC Foundation

Beacon carries the current root-zone DS trust-anchor set for KSK-2017 and KSK-2024. The validator supports DS-to-DNSKEY authentication, DNSKEY RRset authentication, RRSIG validity-window and cryptographic verification, secure parent-to-child trust carry, and terminal positive-RRset validation.

Iterative queries explicitly request DNSSEC material with EDNS and the DO bit.

## Beacon NSEC Authenticated Denial

`internal/gcdns/dnssec_nsec.go` provides the current conservative authenticated-denial layer.

Implemented behavior includes:

- signed exact-owner NSEC proof for an intentionally unsigned child delegation;
- requirement that the delegation proof advertises NS, omits DS, and does not represent an SOA-bearing zone apex;
- preservation of `DNSSECInsecure` below a proven unsigned delegation;
- skipping child DNSKEY retrieval after an insecure delegation has been authenticated;
- signed exact-owner NSEC NODATA validation when the bitmap omits the requested type and CNAME;
- DNSSEC canonical-name interval processing, including NSEC wrap-around intervals;
- conservative empty-answer NXDOMAIN validation requiring an authenticated exact closest encloser, a covering NSEC for the next-closer name, and a covering NSEC for the corresponding wildcard;
- authenticated-zone boundary checks for NXDOMAIN proof material;
- fail-closed behavior for unsigned, invalid, malformed, or unproven denial material.

The NXDOMAIN proof is deliberately stricter than the minimum layouts DNSSEC permits. If an authority provides a valid compact proof that does not contain the explicit closest-encloser NSEC Beacon currently requires, the result remains indeterminate rather than being trusted optimistically.

NSEC3 authenticated denial, wildcard-expanded positive-answer proof, and broader compact NSEC proof support remain staged work.

## Security boundary

The native foundation currently enforces source-level invariants for DNSSEC validation, DNS rebinding protection, explicit recursion and administration ACLs, no accidental open recursion, bogus-result rejection before cache insertion, bounded cache/scheduler/transport behavior, delegation depth and loop protection, in-bailiwick glue acceptance, root trust anchors, DS/DNSKEY authentication, terminal positive RRset validation, conservative NSEC insecure-delegation proof, exact-owner NSEC NODATA proof, and conservative NSEC NXDOMAIN closest-encloser/next-closer/wildcard proof.

These are development controls, not production acceptance evidence.

## Production boundary

No production traffic is routed through `internal/gcdns` yet. Existing AdGuard Home and Unbound runtime behavior remains unchanged until the native path has executable parity, tests, security validation, migration procedures, rollback procedures, and explicit production acceptance.

## Next implementation sequence

1. Implement NSEC3 authenticated denial for NXDOMAIN, NODATA, and insecure delegations.
2. Extend NSEC wildcard handling to wildcard-expanded positive answers and supported compact denial layouts.
3. Complete signed CNAME/DNAME chain handling and out-of-bailiwick nameserver discovery.
4. Implement QNAME minimization, forward/conditional/stub routing, and split-horizon routing.
5. Add persistent cache, prefetch/auto-prefetch, encrypted DNS, authoritative DNS, filtering, DHCP, clustering, APIs, identity, and Glaze UI administration.
6. Validate the competitive-superset requirement with feature, security, privacy, control, resilience, and operational acceptance matrices.
7. Perform controlled migration and production replacement only after GoreeCloud release and production-readiness gates pass.
