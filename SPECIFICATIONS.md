# GoreeCloud DNS Specifications

## Status

GoreeCloud DNS is in active development. GoreeCloud Beacon is the first-party native resolver and DNS policy-control destination. The repository retains inherited AdGuard Home material as a controlled compatibility/migration base while native Beacon capabilities are developed and accepted.

The canonical product record is maintained in Google Drive under `GoreeCloud/Projects/Project Specification — DNS`. This file is the repository-local, version-coupled implementation specification and must not override that canonical record.

Production DNS authority has **not** migrated. Existing AdGuard Home and Unbound production responsibilities remain unchanged until explicit migration acceptance is complete.

## Native Beacon implementation boundary

Current first-party `internal/gcdns` implementation includes:

- validating recursive-resolution foundations;
- DNSSEC validation policy, trust-anchor lifecycle, recovery, and reconciliation evidence;
- QNAME minimisation and referral discovery;
- CNAME/DNAME alias-chain validation;
- routed/private DNSSEC trust-carry behavior;
- resolver routing and locally validating forwarding boundaries;
- classic UDP/TCP downstream transport adaptation into the native Beacon pipeline;
- Beacon Policy Profiles with deterministic assignment and precedence;
- exact, suffix, category, and service policy rules;
- scheduled allow/block/rewrite behavior;
- family/category controls and reviewed SafeSearch mappings;
- privacy-minimized policy decisions and aggregate statistics;
- SHA-256-bound filter-list compilation using a conservative DNS-domain syntax;
- immutable filter-list snapshot lifecycle controls for source identity, HTTPS provenance URI, publisher identity, monotonic sequence, freshness/expiry, content and metadata digests, bounded retained rollback, and fail-closed integrity checking.

## Filter-list lifecycle boundary

`PolicyFilterListLifecycle` performs no remote network acquisition. It accepts already-supplied immutable snapshots only after validating their provenance fields, freshness window, source identity, sequence, content size, and SHA-256 identity. Updates must advance sequence monotonically for the same source; the prior active snapshot is retained for bounded rollback; expired rollback candidates are rejected.

`MetadataSHA256` identifies reviewed metadata bytes. It is **not** a digital-signature verification result. Authenticated remote acquisition, signed metadata verification, source key trust, scheduled refresh, durable Everkeep-backed storage/recovery, and production activation remain separate work.

## Acceptance and authority boundary

Beacon migration evidence is fail closed and cannot transfer production authority from source code or CI. Production migration requires retained evidence for resolver parity, DNSSEC behavior, listener/request-path operation, encrypted DNS where in scope, cache behavior, restart/failure handling, performance, privacy/security, backup/restore, rollback, policy administration, Identity integration, required platform systems, and reversible migration.

## Platform boundaries

GoreeCloud DNS must integrate applicable current contracts from Privacy Shield, Wardveil Security, Everkeep, Glaze UI, GoreeCloud Mesh, and GoreeCloud Identity while preserving each system's independent authority. GoreeCloud Network / Conduit remains authoritative for private network connectivity and assigned network paths; Gateway remains authoritative for ingress/publication; Beacon remains responsible for DNS resolution and DNS policy within its accepted scope.

## Production non-claims

- Native Beacon is not yet production-authoritative.
- The filter-list lifecycle does not fetch remote lists or verify signatures.
- Current source-level policy capabilities do not establish a finished administration UI, multi-user RBAC, production analytics, managed provider catalogs, or production encrypted-DNS profile delivery.
- CI success is acceptance evidence only for the checks actually performed.
