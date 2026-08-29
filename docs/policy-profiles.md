# GoreeCloud Beacon Policy Profiles

Beacon Policy Profiles are the first-party GoreeCloud DNS policy-control layer for reusable client and network DNS behavior.  They are inspired by the useful policy-management capability envelope of products such as NextDNS and Control D, but they are implemented as GoreeCloud-owned source, runtime contracts, and decision rules.  No NextDNS or Control D hosted control plane is required.

## Current source foundation

`internal/gcdns/policy_profiles.go` implements the native `Policy` interface already used by the Beacon request pipeline.  The source foundation provides:

- reusable named policy profiles;
- exact client-ID assignment;
- longest-prefix network assignment;
- a required default profile;
- explicit custom exact-domain and DNS-suffix rules;
- local first-party category and service catalogs represented by DNS suffix membership;
- schedule-aware rule activation with IANA timezone support, selected weekdays, ordinary daytime windows, overnight windows, and deterministic clock injection for testing;
- explicit allow, block, and DNS-rewrite actions;
- NXDOMAIN or REFUSED block responses;
- A, AAAA, ANY, and CNAME rewrite behavior with bounded explicit TTLs;
- deterministic rule precedence independent of configuration-array ordering;
- normalization hardening for profile references and category/service catalog identifiers; and
- privacy-minimized decision recording that does not include the queried domain, client IP address, client identifier, or matched catalog/domain value.

## Assignment precedence

Profile assignment is deterministic:

1. an exact `ClientID` assignment wins;
2. otherwise the longest matching client network prefix wins;
3. otherwise the configured default profile applies.

Conflicting duplicate client or network assignments fail closed at engine construction.

## Rule precedence

Rules are compiled into a deterministic order:

1. higher numeric priority first;
2. for equal priority, exact-domain rules precede suffix rules, service rules, and category rules;
3. equal-priority/equal-kind ties are ordered by stable rule ID.

An explicit allow rule therefore functions as a bypass/exception when it has higher precedence than a broader block.  This makes policy behavior explainable and prevents input-array order from becoming an undocumented security boundary.

## Schedules

Schedules use local wall-clock time in an explicit IANA timezone.  An empty weekday list means every day.  Equal start and end minutes mean the entire selected day.  Overnight schedules attribute the after-midnight portion to the previous day so a Monday 22:00–06:00 policy remains active at Tuesday 01:00.

## Categories and services

The current category/service layer is intentionally local and deterministic.  `PolicyCatalog` maps first-party category or service identifiers to DNS suffixes.  Rules reference those identifiers instead of embedding a proprietary remote classification dependency.

Normalized category/service identifiers must be unique.  Case or surrounding whitespace cannot create two different entries that normalize to the same identifier; such configuration fails closed rather than depending on Go map iteration order.

Future catalog work may add signed catalog packages, catalog revision identities, controlled update channels, richer domain intelligence, and policy-admin tooling.  Any such work must preserve reviewability, provenance, rollback, privacy, and offline/local operation requirements.

## Privacy-safe decision trace

`PolicyDecision` records only:

- selected profile ID;
- selected rule ID;
- action;
- assignment scope (`client`, `network`, or `default`); and
- match kind.

It intentionally omits raw queried names, source addresses, client identifiers, and matched rule/catalog values.  Raw query logging is a separate explicitly governed DNS observability concern and must not be enabled merely to support policy decision tracing.

## Privacy-safe aggregate policy statistics

`internal/gcdns/policy_stats.go` implements a local `PolicyDecisionRecorder` that aggregates counters by profile, rule, action, assignment scope, and match kind.  Snapshots are deterministic and contain no queried domain, client address, client identifier, or matched domain/catalog value.

The recorder is concurrency-safe and supports explicit counter reset without modifying profiles, assignments, DNS cache state, or other DNS configuration.  This provides an initial Beacon Insights policy-metrics source without requiring raw query retention or a vendor-hosted analytics service.

These aggregate counters are not a complete analytics product.  Retention policy, persistence, export, deletion, per-user visibility, dashboards, and any raw-query analytics remain separate governed capabilities subject to Privacy Shield and production acceptance.

## Current boundary

This source milestone does **not** claim complete NextDNS or Control D feature parity.  It establishes the first executable first-party profile/assignment/rule/schedule/rewrite core plus privacy-safe aggregate policy counters on which additional Beacon Shield, Beacon Insights, and Beacon Console functionality can be built.

Still required before production policy replacement includes broader filtering-list ingestion and integrity, managed category/service catalog content, parental-control presets, SafeSearch enforcement, profile CRUD APIs, multi-user/RBAC administration, device enrollment and identity binding, encrypted-DNS profile delivery, richer analytics with retention/export/deletion controls, configuration export/import, cluster synchronization, Glaze UI administration, performance/load testing, backup/recovery, migration/rollback evidence, and explicit production acceptance.

## Production boundary

The policy profile engine and aggregate statistics remain on the isolated Beacon development branch.  They do not transfer production listener ownership, alter current AdGuard Home filtering, modify Unbound, change GoreeCloud Network/NetBird DNS assignment, change DHCP or authoritative DNS, or authorize production cutover.
