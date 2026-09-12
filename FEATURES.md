# GoreeCloud DNS — Features

GoreeCloud DNS is under active fork-to-native development. This file describes the feature state of this repository line and separates it from parallel native Beacon development and the broader product target. Source implementation, CI validation, migration acceptance, production authority, and Stable status are separate evidence states.

## Current source capabilities on this development line

- AdGuard Home-derived DNS serving and administration foundation retained for controlled migration and compatibility.
- Existing inherited network-wide filtering, client handling, query administration, and DNS configuration behavior preserved during transition.
- GoreeCloud DNS product identity and repository governance foundation.
- Glaze UI migration work across dashboard, setup, login, and dense administration surfaces.
- Semantic light/dark surface hierarchy, accessible focus/target treatment, adaptive layouts, and local presentation resources.
- Product-identity and Glaze UI source-contract validation.
- Linux, macOS, and Windows repository test workflows.
- Frontend ESLint, TypeScript, unit-test, production-build, and browser-e2e validation paths.
- GoreeCloud Platform Contract v0.2 declaration and repository-local conformance record.
- GoreeCloud Beacon feature-family taxonomy and target architecture documentation.

## Parallel native Beacon source development

A separate controlled development branch is implementing first-party `internal/gcdns` capabilities including resolver, cache, DNSSEC, routing, policy-profile, privacy-safe statistics, family/SafeSearch, and integrity-bound filter-list foundations.

Those native capabilities are **not merged into this source line at this revision** and therefore are not listed here as current executable capabilities of this branch. Their source, tests, CI, migration evidence, and production acceptance must be evaluated on their own exact revisions before they can be promoted into a merged GoreeCloud DNS release.

## Beacon capability families — target envelope

The following families define the intended first-party GoreeCloud DNS capability domains. A family may be unimplemented, partially implemented on another development line, or awaiting acceptance.

- **Beacon Resolver** — recursion, forwarding, conditional/stub resolution, concurrency, latency-aware selection, DNSSEC validation, QNAME minimization, failover, encrypted forwarding, and resolver hardening.
- **Beacon Cache** — positive/negative/aggressive-negative caching, TTL controls, serve-stale, prefetch, auto-prefetch, persistence, sharding, statistics, and recovery.
- **Beacon Zones** — internal/public authoritative DNS, primary/secondary zones, local/forwarder/stub/catalog zones, transfer/notify, split horizon, and DNSSEC signing.
- **Beacon Shield** — DNS filtering, block/allow policy, wildcard/regex rules, response-policy behavior, client/subnet policy, private-address protections, and rebinding protection.
- **Beacon Secure DNS** — DoH, DoT, DoQ, encrypted forwarding, certificates, and transport policy.
- **Beacon DHCP** — leases and automatic DNS registration.
- **Beacon Horizon** — split horizon, network-aware answers, private-domain routing, conditional forwarding, geolocation-aware answers where approved, and DNS64.
- **Beacon Cluster** — configuration/zone/policy coordination, redundancy, health-aware operation, and recovery across independently serving nodes.
- **Beacon Console** — Glaze UI administration, troubleshooting, query inspection, zone/policy management, DHCP, clustering, health, and runtime control.
- **Beacon API** — scoped automation, orchestration, configuration, runtime administration, cache control, and statistics APIs.
- **Beacon Identity** — multi-user administration, RBAC, scoped permissions, API tokens, TOTP, OIDC, and approved GoreeCloud Identity integration.
- **Beacon Insights** — privacy-aware query/audit/statistics/health information, resolver/upstream state, cache and DNSSEC outcomes, authoritative/DHCP/cluster state where implemented, metrics, and dashboards.
- **Beacon Extensions** — controlled extension points for advanced filtering, horizon logic, DNS64, geolocation, forwarding, policy, and custom DNS processing.

## Beacon Insights Overview — current development target

The Beacon Insights Overview is being implemented on a stacked UI development branch as the intended default Beacon Console landing page. Its defined scope includes privacy-safe aggregate query/protection metrics, service/listener and relevant address state, client counts, resolver/upstream health and latency, and a DNS Resolution Path. Raw query names, client identities, and private address inventories are not required for the default overview and remain governed administrative detail.

Until that branch is reconciled and accepted, the overview is not a current feature of this foundation line and does not represent production observability.

## Required but not production-complete

The broader GoreeCloud DNS replacement still requires, as applicable:

- complete original GoreeCloud-owned native request-path integration;
- full filtering/policy replacement independent of inherited complete-product logic;
- production-capable recursive and forwarded resolution;
- complete DNSSEC validation and trust-anchor lifecycle;
- authoritative DNS and zone lifecycle support;
- encrypted DNS listeners/forwarding;
- integrated DHCP and clustering where retained in release scope;
- first-party API and multi-user administrative authorization;
- accepted Beacon Console and Beacon Insights experiences;
- current accepted Glaze UI, Wardveil Security, Privacy Shield, Everkeep, GoreeCloud Identity, and GoreeCloud Mesh integrations;
- dependency/security remediation and release provenance;
- backup, restore, recovery, portability, migration, rollback, monitoring, and alerting evidence;
- target-environment, performance, accessibility, failure, production-acceptance, and stabilization evidence;
- retirement of inherited AdGuard Home and external Unbound production responsibilities only after explicit cutover acceptance.

## Status rule

A feature may be described as current on a source line only when that line contains the executable implementation. A passing source or CI check establishes only the validation it actually performed. Production acceptance and Stable status require their separate exact-candidate gates.
