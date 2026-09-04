# GoreeCloud Beacon Policy Profiles

Beacon Policy Profiles are the first-party GoreeCloud DNS policy-control layer for reusable client and network DNS behavior. They are inspired by the useful policy-management capability envelope of products such as NextDNS and Control D, but they are implemented as GoreeCloud-owned source, runtime contracts, and decision rules. No NextDNS or Control D hosted control plane is required.

## Current source foundation

`internal/gcdns/policy_profiles.go` implements the native `Policy` interface already used by the Beacon request pipeline. The source foundation provides reusable named policy profiles; exact client-ID assignment; longest-prefix network assignment; a required default profile; explicit exact-domain and DNS-suffix rules; local first-party category and service catalogs; timezone-aware schedules; allow, block, and DNS-rewrite actions; NXDOMAIN or REFUSED blocking; A, AAAA, ANY, and CNAME rewrites; deterministic rule precedence; normalization hardening; and privacy-minimized decision recording.

`internal/gcdns/policy_family.go` adds a first-party compiler for scheduled family controls and DNS-level SafeSearch enforcement. It converts family category blocks, service/application blocks, and reviewed SafeSearch domain-to-target mappings into ordinary `PolicyRule` values so they inherit the existing profile assignment, precedence, scheduling, decision-tracing, and synthetic-response behavior rather than creating a parallel policy engine.

`internal/gcdns/policy_filterlist.go` adds integrity-bound DNS-domain filtering-list ingestion. Reviewed list bytes must be accompanied by their exact SHA-256 digest before they can compile into ordinary Beacon profile rules.

## Assignment precedence

Profile assignment is deterministic: exact `ClientID` assignment wins, otherwise the longest matching network prefix wins, otherwise the configured default profile applies. Conflicting duplicate client or network assignments fail closed.

## Rule precedence

Rules are compiled in deterministic order: higher numeric priority first; then exact-domain, suffix, service, and category specificity; then stable rule ID. Explicit higher-precedence allow rules therefore provide auditable exceptions to broader blocks without making configuration-array order a security boundary.

Filtering-list allow exceptions are not left to rule-ID ordering. `@@` entries compile one priority level above block entries from the same list, making their exception semantics explicit while still allowing a separately configured higher-priority policy to override them.

## Schedules

Schedules use local wall-clock time in an explicit IANA timezone. An empty weekday list means every day. Equal start and end minutes mean the entire selected day. Overnight schedules attribute the after-midnight portion to the previous day so a Monday 22:00–06:00 policy remains active at Tuesday 01:00.

Generated family and filtering-list rules receive independent copies of the configured schedule so later mutation of one generated rule cannot silently modify the schedule on sibling generated rules.

## Categories and services

`PolicyCatalog` maps first-party category or service identifiers to DNS suffixes. Normalized category/service identifiers must be unique. Case or surrounding whitespace cannot create two entries that normalize to the same identifier. Future managed catalogs must preserve provenance, reviewability, integrity, rollback, privacy, and local/offline operation requirements.

Family controls reference those same category and service identifiers rather than introducing a second catalog format. Unknown catalog references therefore continue to fail closed when the profile engine is constructed.

## Family controls and SafeSearch

`BuildFamilyPolicyRules` compiles a `PolicyFamilyConfig` into deterministic ordinary Beacon policy rules. The current source behavior supports scheduled category blocking, scheduled service/application blocking, configurable NXDOMAIN or REFUSED block responses, and one or more DNS-level SafeSearch mappings.

Each `PolicySafeSearchEnforcement` contains a stable local ID, one or more protected DNS suffixes, a reviewed CNAME target, and an optional TTL. The generated SafeSearch rewrite is paired with a same-priority exact target exemption. Because exact rules outrank suffix rules at equal priority, a safe target located beneath its protected suffix cannot recursively rewrite to itself.

SafeSearch configuration also fails closed on ambiguous mappings. A protected domain cannot equal its own target. Two differently targeted mappings cannot claim overlapping protected suffixes, and a target cannot fall beneath another differently targeted mapping's protected suffix where the generated target exemption would silently bypass that other mapping.

The compiler deliberately does not hard-code third-party provider catalogs or claim that every public search/video service is already covered. Reviewed provider/domain mappings remain configuration inputs until GoreeCloud establishes a managed first-party catalog with provenance, integrity, update, rollback, privacy, and offline behavior. This keeps the enforcement mechanism first-party without turning external service metadata into an undocumented runtime dependency.

## Integrity-bound filtering lists

`BuildPolicyFilterListRules` accepts one reviewed `PolicyFilterListConfig` snapshot and requires a matching 64-character hexadecimal SHA-256 before parsing begins. A missing, malformed, or mismatched digest fails closed. The current source compiler is intentionally local and snapshot-based; it does not download remote lists, follow redirects, trust mutable URLs, or silently refresh content.

The parser is resource bounded to an 8 MiB snapshot, 500,000 lines, and 4096 bytes per line. It accepts a conservative DNS-oriented subset: bare domain names, `||domain^` domain anchors, `@@` allow exceptions, and hosts-file entries using only conventional sinkhole addresses `0.0.0.0`, `127.0.0.1`, `::`, or `::1`. Browser-only filtering syntax, arbitrary hosts-file destination addresses, and unsupported multi-field syntax are rejected instead of being guessed.

All accepted names are normalized through the same DNS-name normalizer used by the profile engine. Equivalent duplicate entries collapse deterministically. A domain that appears as both allow and block in the same reviewed snapshot is rejected as an ambiguous configuration. Generated rule IDs are stable counters and do not embed the filtered domain name, preserving the existing privacy-minimized decision-record structure.

This is an integrity-bound ingestion primitive, not yet a full managed-list lifecycle. Remote acquisition, authenticated provenance, signed metadata, update scheduling, freshness/expiry policy, rollback history, list-source trust, delta handling, multi-list conflict policy, and Everkeep-backed recovery remain additional implementation stages.

## Privacy-safe decision trace

`PolicyDecision` contains only selected profile ID, selected rule ID, action, assignment scope, and match kind. It intentionally omits raw queried names, source addresses, client identifiers, and matched rule/catalog values. Raw query logging remains a separately governed observability capability.

Generated family, SafeSearch, and filtering-list rules use ordinary policy IDs and therefore flow through the same minimized decision recorder. Enabling these controls does not require a separate raw-query telemetry path.

## Privacy-safe aggregate policy statistics

`internal/gcdns/policy_stats.go` aggregates counters by profile, rule, action, assignment scope, and match kind. The recorder is concurrency-safe, produces deterministic snapshots, supports explicit reset, and contains no queried domain, client address, client identifier, or matched domain/catalog value. This is an initial Beacon Insights policy-metrics source without raw-query retention or a vendor-hosted analytics dependency.

## GoreeCloud platform boundaries

Beacon Shield owns DNS filtering and DNS-policy enforcement inside GoreeCloud DNS. Wardveil Security remains responsible for broader protection, detection, trust, verification, and response. Privacy Shield governs consent, minimization, retention, data control, and privacy behavior for policy-related data. GoreeCloud Identity will supply approved identity, credential, session, device, and delegated-authority context where identity-aware policy is implemented; DNS resolution is not itself an authorization grant. Everkeep governs backup, recovery, preservation, portability, and continuity. Glaze UI governs accessible and responsive policy administration. GoreeCloud Mesh may coordinate supported cross-platform capabilities and events without becoming DNS resolver or policy authority.

Family controls and filtering-list enforcement remain DNS-policy capabilities. They do not authorize general device management, application execution control, content inspection, transparent proxying, or non-DNS traffic steering.

## Source-validation boundary

`internal/gcdns/policy_profiles_test.go`, `internal/gcdns/policy_profiles_hardening_test.go`, `internal/gcdns/policy_family_test.go`, `internal/gcdns/policy_filterlist_test.go`, and `internal/gcdns/policy_stats_test.go` define deterministic behavioral, family/SafeSearch, integrity/list-parser, hardening, and privacy regression tests. `scripts/validate_policy_profiles.py` is wired into the `beacon-native-core` lint job before `go test ./internal/gcdns` and fails closed if the required engine, family compiler, filter-list compiler, tests, statistics, identity documentation, or platform-boundary markers disappear.

A committed test or validator is not evidence that it passed. Exact-head GitHub Actions or equivalent executable evidence remains required before source acceptance is promoted. Exact workflow run IDs and transient CI status belong in pull-request, acceptance-evidence, and changelog records rather than this durable source contract.

The policy foundation remains development-only until exact-head lint/build/runtime evidence is successful and the wider GoreeCloud DNS migration gates are satisfied.

## Current boundary

This source milestone does **not** claim complete NextDNS or Control D feature parity. It establishes the first executable first-party profile/assignment/rule/schedule/rewrite core, privacy-safe aggregate policy counters, family/SafeSearch rule compiler, and integrity-bound local DNS filtering-list compiler on which additional Beacon Shield, Beacon Insights, and Beacon Console functionality can be built.

Still required before production policy replacement includes managed filter-list acquisition and authenticated provenance/update/rollback lifecycle; managed category/service/SafeSearch catalog content; wildcard/regular-expression custom filtering; temporary overrides and safe profile composition; profile CRUD APIs; multi-user/RBAC administration; device enrollment and identity binding; encrypted-DNS profile delivery; richer analytics with retention/export/deletion controls; configuration export/import; cluster synchronization; Glaze UI administration; performance/load testing; backup/recovery; migration/rollback evidence; and explicit production acceptance.

## Production boundary

The policy profile engine, family/SafeSearch compiler, filter-list compiler, and aggregate statistics remain on the isolated Beacon development branch. They do not transfer production listener ownership, alter current AdGuard Home filtering, modify Unbound, change GoreeCloud Network/NetBird DNS assignment, change DHCP or authoritative DNS, or authorize production cutover.
