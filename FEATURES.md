# GoreeCloud DNS Features

This file separates implemented native Beacon behavior from accepted future scope. Inherited AdGuard Home behavior is not automatically a GoreeCloud Beacon feature claim.

## Implemented native Beacon foundations

- Validating recursive resolver foundations.
- DNSSEC validation policy and trust-anchor lifecycle controls.
- QNAME minimisation, referral discovery, and alias-chain validation.
- Resolver routing, private/stub routing, and locally validating forwarding boundaries.
- UDP/TCP downstream request adaptation into the Beacon pipeline.
- Policy Profiles with default, exact-client, and longest-prefix network assignment.
- Deterministic exact/suffix/category/service rule precedence.
- Scheduled allow, block, and DNS rewrite actions.
- Family/category policy compilation.
- Reviewed DNS-level SafeSearch mapping compilation with ambiguity safeguards.
- Privacy-minimized policy decision records and aggregate statistics.
- Integrity-bound filter-list compilation from exact SHA-256-reviewed content.
- Conservative bare-domain, DNS-anchor, allow-exception, and sinkhole-hosts syntax.
- Filter-list size/line bounds, normalized deduplication, and conflict rejection.
- Immutable filter-list lifecycle validation for source ID, HTTPS source URI, publisher, monotonic sequence, freshness/expiry, metadata/content hashes, source continuity, and retained rollback.
- Defensive copies of lifecycle-owned filter content so callers cannot mutate active state after acceptance.

## Accepted but not yet complete

- Authenticated remote filter-list acquisition.
- Signed metadata verification and source-key trust policy.
- Scheduled managed updates and offline behavior.
- Durable Everkeep-backed filter-list state and rollback history.
- Multi-list composition/conflict controls.
- Managed category/service/SafeSearch catalogs.
- Wildcard and regular-expression policy where safely scoped.
- Temporary overrides and safe profile composition.
- Profile CRUD/admin APIs, multi-user RBAC, and GoreeCloud Identity binding.
- Encrypted-DNS profile delivery.
- Rich privacy-governed analytics.
- Configuration export/import and cluster synchronization.
- Complete Glaze UI administration.
- Production resolver/listener migration and acceptance.

## Explicit non-claims

- A mutable filter-list URL is not trusted merely because it uses HTTPS.
- A metadata SHA-256 digest is not a signature.
- Native policy tests do not prove production DNS migration readiness.
- Existing production DNS authority remains unchanged.
