# GoreeCloud DNS

GoreeCloud DNS is GoreeCloud's DNS filtering, policy, private-service-discovery, resolver, DNS security, and administration project. The repository is currently in **Development** and is not a Stable or production-accepted GoreeCloud DNS release.

The repository began from AdGuard Home as a controlled migration and compatibility foundation. The governing target is an original GoreeCloud-owned DNS application and service. Inherited complete-product code, user interface, workflows, and architecture are transitional and cannot establish final Stable status.

## Current repository state

This development line contains the GoreeCloud DNS product-identity and Glaze UI migration foundation, cross-platform build/test workflows, browser acceptance coverage, repository governance records, and the machine-readable GoreeCloud Platform Contract.

The native GoreeCloud Beacon DNS core is being developed on a separate controlled development branch and is not represented here as merged, production-authoritative, or accepted merely because related specifications describe the target architecture.

The current Platform Contract records GoreeCloud DNS as `development` and `nonconformant`. Required GoreeCloud Manager, Privacy Shield, Wardveil Security, Everkeep, Glaze UI, GoreeCloud Mesh, and GoreeCloud Identity acceptance remains incomplete or blocked as recorded in [`goreecloud.platform.yaml`](goreecloud.platform.yaml).

## Product direction

The accepted product direction is a single GoreeCloud DNS responsibility model that progressively owns:

- client-facing DNS service and access policy;
- advertisement, tracker, malware, phishing, telemetry, and unwanted-domain filtering;
- client, network, family, and policy-profile controls;
- private DNS and GoreeCloud service discovery;
- recursive and forwarded resolution;
- caching and DNSSEC validation;
- authoritative DNS where approved;
- encrypted DNS transports where approved;
- DHCP and clustering where implemented and accepted;
- privacy-conscious query visibility, auditing, health, and statistics;
- first-party administration and API boundaries.

GoreeCloud Beacon is the capability umbrella inside GoreeCloud DNS. Beacon does not create a separate product or transfer DNS runtime authority to another GoreeCloud service.

## User interface

The browser administration experience is migrating toward the current applicable Stable Glaze UI contract. Current source work includes GoreeCloud product identity, semantic surfaces, adaptive layout, accessible focus/target treatment, local presentation resources, and setup/login/dashboard migration work.

This source work is **migration-required**, not final Glaze UI acceptance. A successful source validator or build does not by itself establish rendered, accessibility, form-factor, target-environment, or Stable-release acceptance.

The Beacon Insights Overview is being developed as the future default Beacon Console landing page with privacy-safe aggregate DNS activity, listener/address state, client counts, filtering outcomes, resolver/upstream health, latency, and a DNS Resolution Path. Raw query/client/address detail must remain inside authorized administrative drill-downs and is not required merely to populate the overview.

## Build and validation

The repository Makefile defaults to the inherited `client_v2` path. GoreeCloud-controlled frontend development currently uses `CLIENT_DIR=client` explicitly.

Typical development commands are:

```sh
make CLIENT_DIR=client deps
make CLIENT_DIR=client quick-build
make CLIENT_DIR=client lint test js-typecheck
```

Browser end-to-end validation uses the `js-test-e2e` target after Playwright browser dependencies are installed:

```sh
make CLIENT_DIR=client js-test-e2e
```

GitHub Actions exercises Linux, macOS, and Windows repository tests together with GoreeCloud frontend lint, TypeScript, unit-test, production-build, source-contract, and browser-e2e gates on applicable development changes. Exact-release acceptance remains tied to the exact candidate revision and cannot be inferred from an earlier workflow run.

## Privacy and security boundary

DNS activity can reveal sensitive browsing, application, device, and user behavior. GoreeCloud DNS therefore requires privacy-by-default handling, data minimization, controlled retention, explicit administrative access, privacy-safe logs and metrics, and no unnecessary raw activity collection for dashboards or platform status consumers.

DNS resolution does not itself grant authorization. Network access, application authentication and authorization, ingress/publication, Privacy Shield, Wardveil Security, and other enforcement boundaries remain independent authorities.

GoreeCloud DNS must not become an unrestricted public recursive resolver. Production configuration, credentials, secrets, listener exposure, firewall state, client DNS assignment, and cutover authority remain outside ordinary development-source changes unless separately approved and accepted.

## Production boundary

Current production DNS authority has **not** transferred to this development work. Existing production DNS services remain authoritative until the native GoreeCloud DNS replacement passes isolated runtime validation, resolver/filtering parity, DNSSEC, encrypted-DNS where applicable, failure/restart, performance, security, privacy, backup/restore, recovery, migration, rollback, platform-integration, exact-artifact, production-acceptance, and stabilization gates.

No branch, pull request, green CI run, dashboard implementation, or source-level native subsystem is sufficient by itself to authorize production cutover or Stable classification.

## Repository documentation

The controlled root documentation set is:

- [`README.md`](README.md) — repository orientation and verified current-state boundary.
- [`SPECIFICATIONS.md`](SPECIFICATIONS.md) — repository-coupled technical and acceptance specification.
- [`FEATURES.md`](FEATURES.md) — implemented and planned capability catalogue with evidence boundaries.
- [`BENEFITS.md`](BENEFITS.md) — intended product value without elevating implementation state.
- [`COMPETITIVE-OBJECTIVES.md`](COMPETITIVE-OBJECTIVES.md) — competitive reference envelope and GoreeCloud differentiation targets.
- [`BRANDING.md`](BRANDING.md) — GoreeCloud DNS and Beacon identity guidance.
- [`USER-MANUAL.md`](USER-MANUAL.md) — current Development operator/user guidance and safety boundaries.

Additional records include:

- [`UPSTREAM.md`](UPSTREAM.md) — upstream provenance and transition relationship.
- [`SECURITY.md`](SECURITY.md) — security reporting and production-safety boundary.
- [`docs/goreecloud-project.md`](docs/goreecloud-project.md) — project architecture and development direction.
- [`docs/glaze-ui-conformance.md`](docs/glaze-ui-conformance.md) — repository-local Glaze UI conformance mapping.
- [`docs/PLATFORM_CONFORMANCE.md`](docs/PLATFORM_CONFORMANCE.md) — current platform-contract conformance record.

The canonical project specification and governance records are maintained in the authoritative GoreeCloud Google Drive hierarchy. Repository documentation must remain consistent with those records while describing the exact source state of this repository.

## Lifecycle

**Release lifecycle: Development.**

GoreeCloud DNS must remain non-Stable until every applicable exact-candidate functional, native-build, Glaze UI, Wardveil Security, Privacy Shield, Everkeep, Identity, Mesh, API, security, dependency, accessibility, observability, backup/restore, recovery, release-provenance, deployment, production-acceptance, and stabilization gate has been satisfied with retained evidence.
