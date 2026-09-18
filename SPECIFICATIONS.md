# GoreeCloud DNS Specifications

## Authority and status

This file is the repository-local, version-coupled technical specification for GoreeCloud DNS. The canonical product specification is maintained in the authoritative GoreeCloud Google Drive hierarchy. When this file and the canonical project record differ, the canonical record governs and this file must be corrected.

**Current lifecycle:** Development  
**Platform Contract state:** nonconformant  
**Production DNS authority:** unchanged; no native GoreeCloud DNS production cutover is authorized by this source line.

## Product boundary

GoreeCloud DNS is intended to become one original GoreeCloud-owned DNS application and service covering client DNS, filtering, policy, private DNS, recursive/forwarded resolution, caching, DNSSEC, authoritative DNS where applicable, encrypted DNS, DHCP where applicable, administration, API access, and privacy-conscious observability.

AdGuard Home and Unbound are migration/reference foundations, not permanent final product-level runtime dependencies. Retained mature protocol or cryptographic libraries may remain only where permitted by GoreeCloud native-build governance; retaining a complete upstream product implementation cannot establish Stable status.

## Current source boundary on this development line

This line currently contains:

- GoreeCloud DNS product-identity adaptation;
- the Glaze UI migration foundation for the inherited browser administration surfaces;
- setup, login, dashboard, dense-administration, accessibility, and responsive-presentation work;
- source contracts for GoreeCloud product identity and Glaze UI usage;
- Linux, macOS, and Windows repository test coverage in GitHub Actions;
- frontend lint, TypeScript, unit-test, production-build, and browser-e2e gates;
- the GoreeCloud Platform Contract and repository-local conformance record;
- controlled repository documentation and branding assets.

The native first-party Beacon resolver/core work is maintained on a separate controlled development branch until it is reconciled, reviewed, validated, and accepted. This document does not claim native resolver code is merged into this line merely because the canonical project specification records that parallel development.

## Target request-path model

The target native request path is:

```text
approved client
  -> GoreeCloud DNS listener
  -> client identity and DNS policy / Beacon Shield
  -> authoritative or private DNS when applicable
  -> Beacon Cache
  -> Beacon Resolver or configured forwarder/upstream
  -> DNSSEC and response processing
  -> client response
```

Presentation layers such as Beacon Console and Beacon Insights observe and administer approved state; they are not DNS enforcement authorities by themselves.

## Beacon capability families

The canonical target organizes first-party capability domains under the GoreeCloud Beacon umbrella, including Beacon Resolver, Cache, Zones, Shield, Secure DNS, DHCP, Horizon, Cluster, Console, API, Identity, Insights, and Extensions.

A Beacon family name is a capability identity, not implementation evidence. Each family must be described as current, partial, planned, or unverified according to actual source and runtime evidence.

## Beacon Insights Overview

The Beacon Console Overview is intended to become a purpose-built Glaze UI dashboard rather than an inherited AdGuard statistics page. The dashboard specification includes:

- listener/service state and relevant DNS addresses;
- known/active client counts without making raw identity exposure the default;
- aggregate query volume and allowed, blocked, filtered, rewritten, failed, and cached outcomes where available;
- privacy-safe policy/filter categories and decisions;
- cache hit/miss/stale behavior;
- recursive/forwarded resolver state;
- upstream/resolver health, success/failure/failover, and latency;
- DNSSEC secure/insecure/bogus/indeterminate outcomes where runtime evidence exists;
- optional authoritative-zone, DHCP, and cluster state only when those subsystems are actually implemented and enabled;
- time-range selection and deep links to authoritative detail pages;
- deliberate loading, empty, unknown, degraded, permission-denied, offline, and error states;
- adaptive layouts, accessibility, reduced-motion/transparency, contrast, and forced-color behavior required by the applicable Glaze UI contract.

Privacy-safe aggregate statistics are the default. GoreeCloud DNS must not collect or retain raw query names, client identifiers, private IP inventories, or other sensitive activity merely to populate the overview. Raw per-query, per-client, and per-address detail is permissible only inside the authorized DNS administrative boundary when access control, logging policy, minimization, masking, retention, deletion, and Privacy Shield requirements allow it.

## Security and privacy invariants

GoreeCloud DNS must:

- reject accidental unrestricted public recursion;
- keep administrative access explicitly authorized and separately protected from DNS client service;
- keep credentials and reusable secrets out of source and ordinary documentation;
- validate security-sensitive configuration and fail safely where a safe closed state exists;
- preserve DNSSEC trust conclusions rather than representing indeterminate or invalid state as secure;
- minimize query logging and telemetry to documented operational need;
- keep status/metrics consumers free of unnecessary raw private activity;
- preserve independent authority boundaries for Privacy Shield, Wardveil Security, GoreeCloud Identity, Everkeep, GoreeCloud Mesh, network connectivity, and publication/ingress systems.

## Platform integration state

The machine-readable authority for repository platform status is [`goreecloud.platform.yaml`](goreecloud.platform.yaml). At this revision the component remains Development/nonconformant and required platform-system acceptance is incomplete.

Repository source or UI references to a platform system do not constitute integration acceptance. Consumer-specific runtime, security, privacy, deployment, recovery, and production evidence remains required.

## Build and test boundary

Repository CI is expected to exercise applicable:

- Go lint/tests/bench/fuzz paths;
- Linux, macOS, and Windows repository tests;
- frontend ESLint and TypeScript;
- frontend unit tests;
- production frontend builds;
- product-identity and Glaze UI source contracts;
- browser end-to-end tests;
- release/snapshot build paths where defined.

The GoreeCloud frontend is selected with `CLIENT_DIR=client`. A green workflow is evidence only for the exact checks and exact revision executed; it does not establish target-environment, security, recovery, production, or Stable acceptance.

## Stable qualification blockers

GoreeCloud DNS cannot be classified Stable while any applicable condition remains unresolved, including:

- inherited complete-product implementation still serving as the GoreeCloud application boundary;
- incomplete native DNS capability and production-equivalent request-path integration;
- incomplete current-Stable Glaze UI consumer acceptance;
- incomplete Wardveil Security, Privacy Shield, Everkeep, GoreeCloud Identity, and GoreeCloud Mesh requirements;
- unresolved critical or release-blocking dependency/security findings;
- incomplete supported API and administration acceptance;
- incomplete backup, restore, recovery, portability, migration, and rollback evidence;
- missing monitoring, health, alerting, or privacy-safe observability required for a critical DNS service;
- incomplete accessibility, performance, failure, target-environment, real-browser/device, and production acceptance;
- missing exact release identity, artifact provenance, checksums/SBOM/signing evidence where required;
- any unresolved stricter DNS-specific production cutover requirement.

## Production and migration rule

Production DNS cutover remains prohibited until the exact native GoreeCloud DNS candidate passes the required isolated and target-environment validation, migration and rollback rehearsal, production acceptance, and stabilization process. Existing production DNS must remain available as the rollback authority until the replacement is explicitly accepted and stabilized.

No source commit, pull request, CI run, dashboard screenshot, release tag, container image, or successful startup is sufficient by itself to establish Stable or production authority.
