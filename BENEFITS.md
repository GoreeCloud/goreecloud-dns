# GoreeCloud DNS — Benefits

This file describes the value GoreeCloud DNS is designed to provide while keeping implemented source progress, migration evidence, and future production claims separate.

## Privacy and ownership

- Moves DNS intelligence, filtering, resolution, policy, administration, and observability toward a first-party GoreeCloud-controlled platform.
- Reduces permanent dependence on external DNS products and proprietary cloud DNS services.
- Uses privacy-aware logging and privacy-minimized policy evidence rather than making raw user DNS activity the default control-plane interface.
- Supports local-first resolution principles and QNAME minimisation where applicable.
- Keeps Privacy Shield, Wardveil Security, Everkeep, GoreeCloud Mesh, GoreeCloud Identity, and DNS authority as explicit responsibility boundaries rather than collapsing them into one trust claim.

## Security

- Establishes fail-safe defaults that do not permit accidental public open recursion.
- Separates DNS-client serving from administrative access and keeps administration loopback-restricted by default in the source configuration model.
- Enables DNSSEC validation by default in the safe configuration model and treats rebinding protection as a core safeguard.
- Native resolver validation, trust-anchor lifecycle controls, deterministic policy precedence, ambiguity rejection, conservative filter syntax, and exact integrity checking favor explicit failure over silent weakening.
- Managed filter acquisition authenticates detached Ed25519 metadata against an explicitly configured local trusted-key store before following the signed content URI, applies HTTPS/host allowlists and byte ceilings, rejects redirects by default, and verifies signed SHA-256 content identity before lifecycle activation.
- Keeps encrypted DNS, authoritative publication, DHCP, clustering, and extensions disabled until deliberately configured and accepted.

## Reliability and resilience

- First-party cache work includes persistent-state safety, stale-policy handling, prefetch selection, and controlled recovery behavior.
- Resolver scheduling is designed for bounded concurrency, timeouts, failover, cancellation, and latency-aware target selection.
- Filter-list lifecycle updates require stable source identity, monotonic sequence, freshness/expiry checks, source continuity, bounded retained history, and rollback primitives.
- The clustering direction requires individual DNS nodes to remain capable of serving independently rather than making a central controller a single point of DNS failure.
- Backup, recovery, migration, and deterministic failover are product requirements rather than optional operational afterthoughts.

## Administrative control

- GoreeCloud Beacon provides one coherent feature system for recursive DNS, authoritative DNS, filtering, encrypted transport, DHCP, horizon logic, clustering, administration, identity, observability, APIs, and extensions.
- First-party APIs and current-Stable Glaze UI administration are intended to make advanced DNS control understandable without requiring a collection of permanent external sidecars.
- Policy Profiles already provide deterministic assignment and precedence foundations for per-client/network policy, while broader multi-user Identity/RBAC administration remains an acceptance target.

## Network-wide protection

- The product direction combines resolver capability with network-wide unwanted-domain filtering for advertisements, trackers, malware, phishing, telemetry, and other policy-defined domains.
- Current Beacon policy foundations include allow/block/rewrite actions, family/category controls, reviewed SafeSearch mappings, deterministic rule precedence, and integrity-bound managed filter lists.
- Advanced wildcard/regular-expression behavior, managed catalogs, and multi-list composition remain bounded future work until their safety and acceptance evidence exists.
- Integration with GoreeCloud Network is designed to provide consistent private DNS and network-aware policy without collapsing the two products into one service.

## Independence and migration discipline

- The fork-to-native strategy lets GoreeCloud preserve mature compatibility behavior during transition while progressively owning the capabilities that define the DNS product.
- Source implementation, CI validation, isolated acceptance, migration rehearsal, and production DNS authority are separate states.
- Core DNS architecture is documented as explicit internal subsystems, making ownership, testing, security review, migration, and future replacement clearer.
- AdGuard Home and Unbound remain production-authoritative until explicit retained evidence and migration approval authorize a later transfer.

## User benefit

The long-term benefit is a single private, secure, resilient, self-hosted DNS platform with strong filtering, validating resolution, deep administrative control, dependable recovery, and no requirement to surrender DNS policy or operational visibility to an outside provider.
