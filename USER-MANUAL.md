# GoreeCloud DNS User Manual

## Current release state

GoreeCloud DNS is currently a **Development** project. This manual describes the controlled development and administrative boundary of the repository; it is not a production-cutover guide and does not represent the native GoreeCloud DNS replacement as Stable or production-authoritative.

The current repository retains inherited AdGuard Home behavior during the transition to an original GoreeCloud-owned DNS application. Some visible workflows therefore remain transitional while GoreeCloud product identity, Glaze UI, Beacon capabilities, security, privacy, recovery, and native runtime work are developed and accepted.

## Before using a development build

Use a development or validation environment that cannot conflict with production DNS. Do not change production client DNS assignment, NetBird/GoreeCloud Network nameserver configuration, DHCP DNS delivery, firewall exposure, public listeners, Caddy/publication state, or production resolver authority as part of ordinary source testing.

Keep an approved rollback path. Never expose a development resolver as unrestricted public recursion.

## Building the controlled frontend

The repository Makefile defaults to an inherited frontend path. GoreeCloud-controlled frontend work uses `CLIENT_DIR=client` explicitly:

```sh
make CLIENT_DIR=client deps
make CLIENT_DIR=client quick-build
```

Useful validation commands include:

```sh
make CLIENT_DIR=client lint
make CLIENT_DIR=client js-typecheck
make CLIENT_DIR=client test
```

The browser end-to-end suite is available through:

```sh
make CLIENT_DIR=client js-test-e2e
```

Playwright browser dependencies must be installed before running browser tests locally. GitHub Actions remains the authoritative retained CI evidence for exact revisions executed there.

## Administration interface

The administration interface is under active GoreeCloud migration. Depending on the branch and development revision, the console may include inherited screens alongside GoreeCloud-controlled product identity and Glaze UI presentation work.

Primary administrative areas include the following capability domains where present in the current revision:

- **Overview / Dashboard** — service and DNS activity summary.
- **Query Log / Queries** — authorized query inspection and troubleshooting.
- **Clients** — client definitions and applicable client-specific behavior.
- **Filters / Protection** — filtering configuration, rules, allow behavior, and protection controls.
- **DNS / Upstream settings** — DNS processing and configured upstream behavior.
- **Settings** — service and administration configuration.

A screen existing in the interface does not prove that a native Beacon backend implements it. Transitional inherited functionality and first-party native functionality must remain distinguishable during development.

## Beacon Insights Overview

The developing Beacon Insights Overview is intended to become the default GoreeCloud DNS landing page. Where the branch and runtime expose supported evidence, it may summarize:

- DNS service/listener state and relevant addresses;
- active or known client counts;
- aggregate query activity;
- blocked, filtered, rewritten, failed, allowed, or cached outcomes;
- policy/protection decisions;
- resolver/upstream health and latency;
- cache and DNSSEC outcomes;
- the DNS Resolution Path from client/listener through policy, cache, resolver/upstream, DNSSEC/result processing, and client response.

The overview is intentionally aggregate-first. Use explicit authorized detail pages for raw query names, client identities, or raw private addresses. Do not enable or retain sensitive query data solely for dashboard decoration.

## Query and client privacy

DNS logs can reveal browsing, applications, devices, users, and behavioral patterns. Operators must follow the configured logging, retention, deletion, masking, access-control, and Privacy Shield requirements applicable to the deployment.

Recommended development behavior is to use the minimum query detail needed for the test being performed. Do not copy real private query logs, client inventories, credentials, or private tokens into source control, screenshots, ordinary issue text, or public test data.

## DNS protection and policy

Filtering and policy controls are DNS enforcement functions only when the trusted runtime actually implements and applies them. The UI must not be treated as the enforcement boundary.

When testing filtering or rewrites:

1. Use a non-production client or isolated test environment.
2. Confirm the intended rule/policy scope.
3. Test both allowed and denied outcomes.
4. Check for accidental broad blocking or bypass.
5. Confirm private service resolution is unaffected unless the test intentionally changes it.
6. Preserve a known-good configuration for rollback.

DNS resolution or a DNS rewrite never grants application authorization. Network, identity, application, and publication controls remain separate.

## Resolver and upstream changes

Changes to recursive, forwarded, bootstrap, or upstream DNS behavior can make the DNS service unavailable or leak queries to unintended destinations. In Development:

- use explicit approved test targets;
- do not point a development resolver at itself;
- do not create unrestricted recursive access;
- verify failure and timeout behavior as well as successful resolution;
- verify private namespaces do not escape to public recursion when policy forbids it;
- treat DNSSEC `indeterminate`, `insecure`, `secure`, and `bogus` as distinct states rather than collapsing them into a generic success result.

## Authentication and administrative access

Administrative access must remain restricted to approved users and networks. Do not weaken authentication, authorization, session protection, or network restrictions to make development testing easier.

Reusable credentials, API keys, private keys, signing secrets, recovery codes, and equivalent secrets must not be committed to the repository or included in ordinary documentation.

## Backup, restore, and recovery

A successful configuration save or backup job is not proof of recoverability. Before a production migration can be accepted, GoreeCloud DNS must have a documented and tested restore path for all required configuration, policy, private DNS data, trusted state, and other persistent material.

During Development, preserve current production DNS and its known-good configuration as the rollback authority. Do not retire existing production DNS merely because a development build starts successfully or passes CI.

## Troubleshooting development builds

For a failed build or test:

- reproduce against the exact branch and commit;
- keep `CLIENT_DIR=client` explicit for GoreeCloud frontend work;
- distinguish frontend, Go/runtime, browser-e2e, source-contract, and platform-contract failures;
- do not delete or weaken a failing gate simply to make CI green;
- correct the implementation, fixture, or accurately stale contract marker and rerun the exact candidate.

For an unavailable DNS service, verify the isolated development listener, configured address/port, resolver/upstream reachability, access controls, and configuration validity before changing network-wide client settings.

## What Development users must not infer

Do not infer any of the following solely from a working interface or green source CI:

- production DNS authority;
- Stable release status;
- completed native resolver replacement;
- accepted Glaze UI conformance;
- accepted Wardveil Security or Privacy Shield integration;
- validated Everkeep recovery;
- validated Identity or Mesh integration;
- safe public exposure;
- completed migration/rollback readiness.

Those states require their own exact-candidate evidence and approvals.

## Related repository records

- [`README.md`](README.md) — current repository orientation.
- [`SPECIFICATIONS.md`](SPECIFICATIONS.md) — version-coupled technical and acceptance specification.
- [`FEATURES.md`](FEATURES.md) — feature catalogue and implementation-state distinctions.
- [`SECURITY.md`](SECURITY.md) — security reporting and production-safety boundary.
- [`goreecloud.platform.yaml`](goreecloud.platform.yaml) — machine-readable platform-conformance state.
- [`docs/PLATFORM_CONFORMANCE.md`](docs/PLATFORM_CONFORMANCE.md) — repository-local platform conformance record.
- [`UPSTREAM.md`](UPSTREAM.md) — inherited foundation/provenance boundary.

The authoritative GoreeCloud project specification and governance records remain in the controlled GoreeCloud Google Drive hierarchy.
