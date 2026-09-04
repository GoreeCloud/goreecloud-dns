# GoreeCloud DNS — Features

GoreeCloud DNS is under active fork-to-native development. This file separates current source capabilities from the broader GoreeCloud Beacon product target. A source capability is not automatically production-accepted, and inherited AdGuard Home behavior is not automatically a GoreeCloud Beacon feature claim.

## Current maintained-fork foundation

- AdGuard Home-derived DNS serving and administration foundation retained during transition
- Existing network-wide DNS filtering and policy behavior available through the inherited foundation
- GoreeCloud product shell, repository governance, security boundaries, and controlled upstream provenance
- GoreeCloud Beacon feature taxonomy for the integrated first-party DNS platform
- AdGuard Home and Unbound remain production-authoritative until explicit migration acceptance and approval

## Current first-party native Beacon source foundation

- First-party `internal/gcdns` request/result, Policy, Authority, Cache, Resolver, and Observer contracts
- Validating recursive resolver foundations, iterative resolution, referral discovery, and alias-chain validation
- DNSSEC validation policy, trust-chain carry, positive terminal-answer validation, denial/wildcard foundations, and trust-anchor lifecycle/recovery controls
- QNAME minimisation with reuse/hardening coverage
- Resolver routing, private/stub routing, routed DNSSEC policy, and locally validating forwarding boundaries
- UDP/TCP downstream request adaptation into the Beacon pipeline
- Native cache foundations with persistence safety, expiration/stale-policy checks, prefetch, and auto-prefetch selection
- Resolver scheduling with bounded concurrent attempts, per-attempt timeouts, first-valid-response cancellation, failover, latency-aware ordering, and privacy-safe target statistics
- Policy Profiles with default, exact-client, and longest-prefix network assignment
- Deterministic exact/suffix/category/service rule precedence and scheduled allow, block, and DNS rewrite actions
- Family/category policy compilation and reviewed DNS-level SafeSearch mappings with ambiguity safeguards
- Privacy-minimized policy decision records and aggregate statistics
- Integrity-bound filter-list compilation from exact SHA-256-reviewed content with bounded size/line handling, normalized deduplication, conservative syntax, and conflict rejection
- Immutable filter-list lifecycle validation for source identity, credential-free HTTPS provenance URI, publisher, monotonic sequence, freshness/expiry, metadata/content hashes, source continuity, retained history, and rollback
- Detached Ed25519 filter-list metadata verification against an explicitly configured local trusted-key store
- Bounded signed HTTPS acquisition that authenticates metadata before content retrieval, requires allowlisted HTTPS authorities, rejects redirects by default, enforces byte ceilings, verifies signed content SHA-256, and then applies the existing lifecycle contract
- Privacy-safe Beacon runtime status with separate configuration validity, native-pipeline completeness, production-authority, and service-availability fields
- Fail-closed `unknown / runtime_health_not_observed` service availability until an authoritative live resolver-health source exists
- Fail-closed migration-readiness evidence that cannot authorize production DNS cutover

## GoreeCloud Beacon feature families

- **Beacon Resolver** — recursion, forwarding, conditional/stub resolution, concurrency, latency-aware selection, DNSSEC validation, QNAME minimisation, failover, encrypted forwarding, and resolver hardening
- **Beacon Cache** — positive/negative/aggressive-negative caching, TTL controls, serve-stale, prefetch, auto-prefetch, persistence, sharding, statistics, and recovery
- **Beacon Zones** — internal/public authoritative DNS, primary/secondary zones, local/forwarder/stub/catalog zones, transfer/notify, split horizon, and DNSSEC signing
- **Beacon Shield** — DNS filtering, block/allow policy, wildcard/regex rules, response-policy behavior, client/subnet policy, private-address protections, and rebinding protection
- **Beacon Secure DNS** — DoH, DoT, DoQ, encrypted forwarding, certificates, and transport policy
- **Beacon DHCP** — leases and automatic DNS registration
- **Beacon Horizon** — split horizon, network-aware answers, private-domain routing, conditional forwarding, geolocation-aware answers, and DNS64
- **Beacon Cluster** — configuration/zone/policy coordination, redundancy, health-aware operation, and recovery across independently serving nodes
- **Beacon Console** — current-Stable Glaze UI administration, troubleshooting, query inspection, zone/policy management, DHCP, clustering, health, and runtime control
- **Beacon API** — scoped automation, orchestration, configuration, runtime administration, cache control, and statistics APIs
- **Beacon Identity** — multi-user administration, RBAC, scoped permissions, API tokens, TOTP, and OIDC
- **Beacon Insights** — privacy-aware query logs, audit, statistics, health, DNSSEC outcomes, cache/resolver/zone/DHCP/cluster state, metrics, and dashboards
- **Beacon Extensions** — controlled extension points for advanced filtering, horizon logic, DNS64, geolocation, forwarding, policy, and custom processing

## Accepted but not yet complete

- An authoritative live resolver-health producer capable of moving Beacon service availability beyond fail-closed `unknown`
- Scheduled managed-filter refresh/retry and offline behavior
- Signing-key rotation/revocation and durable trusted-key storage
- Durable Everkeep-backed filter-list lifecycle state and rollback history
- Multi-list composition and conflict controls
- Managed category/service/SafeSearch catalogs
- Wildcard and regular-expression policy where safely scoped
- Temporary overrides and safe profile composition
- Profile CRUD/admin APIs, multi-user RBAC, and GoreeCloud Identity binding
- Production encrypted-DNS listeners and encrypted forwarding
- Full authoritative DNS and zone lifecycle implementation
- Integrated DHCP
- Clustering and independent multi-node synchronization
- Rich privacy-governed analytics
- Configuration export/import and cluster synchronization
- Complete current-Stable Glaze UI administration
- Production-path integration and acceptance of the complete native resolver/cache/policy pipeline
- Final migration away from permanent AdGuard Home and Unbound runtime dependence after feature, security, recovery, and production acceptance are proven

## Explicit non-claims

- Beacon configuration validity and pipeline completeness are readiness facts, not proof of live resolver availability.
- Beacon service availability does not imply network connectivity, Privacy Shield state, Wardveil Security posture, or Everkeep continuity readiness.
- A mutable filter-list URL is not trusted merely because it uses HTTPS.
- A metadata SHA-256 digest is not a signature.
- Authenticated acquisition source tests do not establish production network trust or production migration readiness.
- Native resolver/policy tests do not prove production DNS migration readiness.
- Existing production DNS authority remains unchanged.

## Status rule

A feature moves from planned or partial to current only after the repository contains the executable implementation and the required validation evidence. Production acceptance remains a separate gate.
