# GoreeCloud DNS

GoreeCloud DNS is the first-party GoreeCloud DNS platform. Its native resolver identity is **GoreeCloud Beacon**.

Beacon is being built to own recursive resolution, caching, DNSSEC validation, private recursion/routing, DNS policy integration, encrypted DNS, authoritative/private-zone service, filtering integration, privacy-safe observability, trust-anchor lifecycle management, and controlled migration from the current production DNS stack.

This repository still contains inherited AdGuard Home compatibility code while the native-by-destination transition is in progress. That inherited product code is a temporary migration bridge, not the long-term GoreeCloud DNS architecture. Production AdGuard Home and Unbound remain authoritative until the native replacement passes explicit migration, backup/restore, rollback, security, privacy, and production-acceptance gates.

## Native Beacon source

The active first-party resolver work is under `internal/gcdns` and currently includes:

- normalized request/result contracts and a policy → authority → cache → resolver pipeline;
- recursive and validating-forwarding behavior with private-routing support;
- DNSSEC validation policy and authenticated-answer handling;
- QNAME minimization and referral/delegation processing;
- positive, negative, stale, and routing-partitioned cache behavior;
- CNAME/DNAME alias handling and compact-denial support;
- persistent protected trust-anchor state, reviewed activation, immutable recovery points, hash-chained lifecycle audit, and isolated activation/recovery rehearsal;
- a native classic-DNS downstream adapter that carries UDP/TCP requests into the Beacon pipeline, records only normalized client transport metadata, rejects malformed multi-question requests, and fails closed with DNS SERVFAIL when native resolution is unavailable;
- fail-closed migration-readiness evidence bound to an exact source revision and immutable runtime-artifact SHA-256.

The downstream adapter is source/integration plumbing only. It is not connected to a production listener in this milestone and does not change client DNS assignment.

## Migration-readiness contract

`goreecloud-beacon-migration-evidence/v1` requires exact-candidate evidence for:

- resolver feature/parity behavior;
- private recursion;
- DNSSEC;
- isolated trust-anchor recovery;
- restart and failure behavior;
- cache behavior;
- encrypted DNS;
- backup/restore;
- rollback;
- privacy-safe observability;
- Privacy Shield;
- Wardveil Security;
- Everkeep;
- the current Stable Glaze UI contract for user-facing administration surfaces.

The currently validated Glaze UI Stable baseline is 1.6.0. Candidate 2.0.0 is not accepted as the Stable migration baseline.

Complete source evidence may make Beacon eligible for an explicitly approved migration rehearsal. It never authorizes production cutover by itself; `production_cutover_authorized` remains false.

## Validation

The Beacon-native workflow validates the native forwarding/source contract and runs `go test ./internal/gcdns`. The workflow explicitly checks out and verifies the exact candidate revision before testing.

Repository-wide inherited build/lint workflows remain useful compatibility evidence, but failures in inherited paths are classified separately unless evidence shows that a Beacon change caused the regression.

## Platform boundaries

- **GoreeCloud DNS / Beacon** owns DNS resolution, caching, DNSSEC, DNS policy, filtering integration, private/authoritative DNS, and encrypted DNS service.
- **GoreeCloud Network / Conduit** may deliver approved DNS configuration to clients but does not own resolver policy.
- **GoreeCloud Gateway** owns HTTPS ingress and reverse proxying, not DNS resolution.
- **Privacy Shield** supplies platform privacy contracts and data-minimization requirements.
- **Wardveil Security** supplies evidence-backed security posture and security experiences.
- **Everkeep** supplies backup, restoration, recovery, portability, and continuity requirements.
- **Glaze UI** governs GoreeCloud-controlled user interfaces.

## Upstream provenance

The inherited compatibility tree originated from AdGuard Home and remains subject to its applicable licenses, notices, source history, and attribution. GoreeCloud preserves that provenance while progressively replacing product features with original first-party Beacon implementations. The native transition does not permit removal of required third-party copyright or license material.

## Production boundary

No source change in this branch transfers production DNS authority. Production AdGuard Home, Unbound, Network/Conduit DNS assignment, filtering, DHCP, authoritative DNS, encrypted DNS endpoints, client resolver configuration, credentials, listeners, forwarding/stub targets, private zones, or production trust-anchor state must remain unchanged until retained acceptance evidence passes and migration is explicitly approved.
