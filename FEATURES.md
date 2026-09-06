# GoreeCloud DNS — Features

GoreeCloud DNS is under active fork-to-native development. This file separates current source capabilities from the broader GoreeCloud Beacon product target. A source capability is not automatically production-accepted.

## Current maintained-fork foundation

- AdGuard Home-derived DNS serving and administration foundation retained during transition
- Existing network-wide DNS filtering and policy behavior available through the inherited foundation
- GoreeCloud product shell, repository governance, security boundaries, and controlled upstream provenance
- GoreeCloud Beacon feature taxonomy for the integrated first-party DNS platform

## Current first-party native source foundation

- First-party `internal/gcdns` request and result model
- First-party Policy, Authority, Cache, Resolver, and Observer interfaces
- Native cache foundations
- Opt-in persistent cache snapshots with versioning, owner-only temporary-file permissions, atomic replacement, and restore-time expiration/stale-policy checks
- Prefetch and auto-prefetch candidate selection
- Resolver scheduling foundation with bounded concurrent target attempts, per-attempt timeouts, first-valid-response cancellation, failover, latency-aware ordering, and privacy-safe target statistics
- Controlled prefetch execution through the native request pipeline
- Classic DNS transport foundation
- Iterative recursion development foundation
- DNSSEC trust-chain carry and positive terminal-answer DNSSEC validation foundations
- Fail-closed source validation for required native subsystem declarations and safety markers
- Safe example configuration that restricts recursion and administration to loopback by default, enables DNSSEC validation and DNS-rebinding protection, and leaves higher-exposure capabilities disabled until explicitly configured

## GoreeCloud Beacon feature families

The following families define the complete first-party product target. Some are partially implemented and some remain planned.

- **Beacon Resolver** — recursion, forwarding, conditional/stub resolution, concurrency, latency-aware selection, DNSSEC validation, QNAME minimization, failover, encrypted forwarding, and resolver hardening
- **Beacon Cache** — positive/negative/aggressive-negative caching, TTL controls, serve-stale, prefetch, auto-prefetch, persistence, sharding, statistics, and recovery
- **Beacon Zones** — internal/public authoritative DNS, primary/secondary zones, local/forwarder/stub/catalog zones, transfer/notify, split horizon, and DNSSEC signing
- **Beacon Shield** — DNS filtering, block/allow policy, wildcard/regex rules, response-policy behavior, client/subnet policy, private-address protections, and rebinding protection
- **Beacon Secure DNS** — DoH, DoT, DoQ, encrypted forwarding, certificates, and transport policy
- **Beacon DHCP** — leases and automatic DNS registration
- **Beacon Horizon** — split horizon, network-aware answers, private-domain routing, conditional forwarding, geolocation-aware answers, and DNS64
- **Beacon Cluster** — configuration/zone/policy coordination, redundancy, health-aware operation, and recovery across independently serving nodes
- **Beacon Console** — Glaze UI administration, troubleshooting, query inspection, zone/policy management, DHCP, clustering, health, and runtime control
- **Beacon API** — scoped automation, orchestration, configuration, runtime administration, cache control, and statistics APIs
- **Beacon Identity** — multi-user administration, RBAC, scoped permissions, API tokens, TOTP, and OIDC
- **Beacon Insights** — privacy-aware query logs, audit, statistics, health, DNSSEC outcomes, cache/resolver/zone/DHCP/cluster state, metrics, and dashboards
- **Beacon Extensions** — controlled extension points for advanced filtering, horizon logic, DNS64, geolocation, forwarding, policy, and custom processing

## Planned / not yet production-complete

- Full authoritative DNS and zone lifecycle implementation
- Complete filtering replacement independent of the inherited AdGuard Home path
- Production encrypted DNS listeners and encrypted forwarding
- Integrated DHCP
- Clustering and independent multi-node synchronization
- Complete NSEC/NSEC3 authenticated denial and authoritative DNSSEC signing
- Full multi-user administration and advanced API/console workflows
- Production-path integration of the complete native resolver/cache pipeline
- Final migration away from permanent AdGuard Home and Unbound runtime dependence after feature, security, recovery, and production acceptance are proven

## Status rule

A feature moves from planned or partial to current only after the repository contains the executable implementation and the required validation evidence. Production acceptance remains a separate gate.
