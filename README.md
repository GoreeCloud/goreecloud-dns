# GoreeCloud DNS

GoreeCloud DNS is the planned client-facing DNS filtering, policy-enforcement, private service-discovery, and DNS security platform for GoreeCloud.

This repository is a GoreeCloud-maintained fork of AdGuard Home. The project begins from the mature AdGuard Home DNS foundation and will be progressively adapted into a distinct GoreeCloud product while preserving applicable upstream licensing, attribution, and source-availability obligations.

## Project Direction

GoreeCloud DNS is intended to provide:

- network-wide advertisement and tracker blocking;
- malicious-domain and threat-domain blocking;
- client-specific DNS policies;
- family and child policy profiles;
- private GoreeCloud DNS records and service discovery;
- custom filtering and allow rules;
- query visibility and privacy-aware diagnostics;
- upstream DNS management;
- approved encrypted DNS capabilities;
- GoreeCloud Network integration for private connectivity and client identity;
- GoreeCloud Monitor integration for DNS observability;
- GoreeCloud Notify integration for operational and security alerts;
- GoreeCloud Backup integration for configuration and recovery;
- GoreeCloud Manager integration for centralized visibility;
- Wardveil Security capabilities for DNS security and policy enforcement.

## Architecture Boundary

The initial production architecture remains:

```text
Approved Clients
      |
      v
GoreeCloud DNS
      |
      v
   Unbound
      |
      v
Internet DNS Authorities
```

GoreeCloud DNS is the client-facing filtering, policy, and private-DNS layer. Unbound remains the recursive, caching, and DNSSEC-validating resolver unless a future approved architecture explicitly changes that responsibility.

## Development Model

The project follows a controlled fork-to-native transition:

```text
AdGuard Home
    -> GoreeCloud-maintained fork
    -> GoreeCloud-native user experience and integrations
    -> increasingly independent internal architecture
    -> GoreeCloud-controlled DNS platform
```

The upstream foundation is an engineering bootstrap, not the final product boundary.

## User Interface

GoreeCloud DNS consumes Stable Glaze UI 1.1 as its design system. Current foundation work includes GoreeCloud DNS product identity, semantic light/dark surfaces, the Canvas/Solid/Raised/Glaze/Overlay hierarchy, accessible target and focus treatment, adaptive layouts, dense administration hardening, and local-only presentation resources.

The independently bundled dashboard, initial setup flow, and login flow all load the same Glaze UI consumer layers and GoreeCloud product-identity adapter. Setup and authentication surfaces are also being migrated away from inherited hard-coded card, shadow, progress, error, and accent presentation values.

Visible localized self-references to the inherited product name are adapted through a controlled identity layer that replaces only the exact `AdGuard Home` product name. Generic upstream references, protocol terminology, filtering syntax, licensing, attribution, and provenance are not generically rewritten.

## Production Safety

The existing production AdGuard Home deployment remains operational during early GoreeCloud DNS development. No production cutover should occur until GoreeCloud DNS has passed isolated runtime, filtering, private-DNS, upstream, failure, backup/restore, performance, security, and rollback validation.

## Repository Documents

- `UPSTREAM.md` — upstream relationship and fork maintenance model.
- `SECURITY.md` — security and production-safety boundary.
- `docs/goreecloud-project.md` — project architecture and development direction.
- `docs/glaze-ui-conformance.md` — Glaze UI consumer conformance and Stable-release boundary.

## Validation Status

Fail-closed source validators cover Stable Glaze UI 1.1 and product identity across the dashboard, setup, and login entrypoints, including the current Query Log and advanced-settings accessibility contracts. For the latest inspected exact head, GitHub returned no pull-request workflow run and no combined commit-status checks. Executable lint, typecheck, tests, production build, and compiled visual/accessibility acceptance therefore remain outstanding rather than inferred from source-marker validation.

## Current Status

GoreeCloud DNS is under active development. Repository, CI, application-shell, localization identity, Stable Glaze UI 1.1, setup, authentication, dense administration, and accessibility foundations are being established before DNS-engine behavior or production migration work begins.
