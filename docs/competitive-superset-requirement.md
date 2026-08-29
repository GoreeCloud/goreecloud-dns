# GoreeCloud DNS Competitive Superset Requirement

GoreeCloud DNS is intended to become a first-party DNS platform that supersedes the combined useful capability envelope of Technitium DNS Server, Pi-hole, AdGuard Home, NextDNS, and Control D in overall DNS capability, security, privacy, policy control, operator control, resilience, observability, and extensibility. This is a product target and acceptance requirement, not a claim that the current development branch already exceeds those products.

The comparison products are reference and inspiration sources only. They are not permanent runtime dependencies, adopted product implementations, hosted control-plane requirements, or evidence that an equivalent GoreeCloud capability is complete. GoreeCloud DNS must implement applicable capabilities as original GoreeCloud-owned software, subject to the project's native-build and narrowly-scoped critical-foundation rules.

## Governing rule

A future stable GoreeCloud DNS release should not require an administrator to deploy Technitium DNS Server, Pi-hole, AdGuard Home, Unbound, NextDNS, Control D, or another proprietary cloud DNS service to obtain a major DNS capability that fits the documented GoreeCloud DNS role. Where a reference product demonstrates a useful capability, Beacon should provide an equivalent or stronger first-party implementation when that capability is applicable to GoreeCloud.

Reference products have different strengths. Technitium DNS Server, Pi-hole, and AdGuard Home remain useful references for self-hosted DNS serving, filtering, administration, and local-network operation. NextDNS and Control D are additional references for profile-oriented DNS policy, per-device and per-network control, category and service filtering, schedules, privacy-aware analytics, custom rules and rewrites, secure DNS endpoint delivery, and API-driven policy management. GoreeCloud DNS should combine the useful concepts without inheriting proprietary implementation, branding, account dependence, or cloud-control assumptions.

## Capability bar

Beacon must cover the combined useful capability envelope of the comparison products where the capability belongs inside GoreeCloud DNS, including:

- recursive resolution, caching, DNSSEC validation, forwarding, conditional forwarding, concurrency, health-aware and latency-aware resolution;
- authoritative primary, secondary, stub, and forwarder zones, catalog zones, AXFR/IXFR, NOTIFY, DNSSEC signing, NSEC/NSEC3, and secure transfer options;
- network-wide advertisement, tracker, malware, phishing, telemetry, service, and custom-domain filtering with allowlists, blocklists, wildcards, regular expressions, client/subnet/group policy, RPZ, and SafeSearch/family policy;
- first-class policy profiles that can be assigned by approved device, client, user, subnet, group, network, or other explicit GoreeCloud identity and network context;
- category filtering and named service/application controls with explicit allow, block, bypass, override, or other supported DNS-policy actions;
- schedules and time-based policy for family, child, productivity, recreation, guest, IoT, infrastructure, and custom use cases;
- SafeSearch, restricted-content modes, and related family protections when the target service provides a technically supportable DNS enforcement mechanism;
- custom DNS rules, local/private rewrites, DNS response overrides, block/allow exceptions, wildcard/regular-expression matching, and controlled DNS-level redirect behavior;
- clear rule precedence, deterministic policy evaluation, and operator-visible decision tracing that explains which profile, rule, list, service control, schedule, or security decision produced a DNS outcome;
- configurable privacy-aware query logging, retention, redaction, export/deletion controls where applicable, per-profile visibility, aggregate statistics, dashboards, and analytics without requiring external product telemetry;
- per-client and per-profile query, blocked-query, error, latency, resolver, cache, DNSSEC, and policy statistics that can be collected without unnecessarily retaining sensitive raw query data;
- DoH, DoT, DoQ, HTTP/3 where appropriate, encrypted forwarding, secure endpoint provisioning, and explicit transport policy;
- integrated DHCP and DNS registration;
- split horizon, geolocation-aware DNS responses, DNS64, advanced forwarding, private namespaces, and controlled processing extensions;
- clustering, centralized multi-node management, configuration/zone/policy synchronization, independent node serving, health visibility, and deterministic failover;
- browser administration, REST/HTTP API, automation, runtime controls, query tools, statistics, dashboards, logs, metrics, backup/recovery, and troubleshooting;
- multi-user administration, RBAC, scoped API tokens, TOTP, OIDC SSO, auditable administration, least-privilege access, and integration with GoreeCloud Identity;
- extensibility comparable to mature DNS application/plugin systems, but with explicit privilege, resource, privacy, observability, disable, recovery, and policy boundaries.

## Policy-control target inspired by NextDNS and Control D

GoreeCloud DNS must treat policy control as a first-party product surface rather than as a loose collection of filter toggles.

The target policy model should support reusable profiles, explicit profile inheritance or composition where safely defined, deterministic assignment precedence, per-client exceptions, temporary overrides, schedules, category controls, service/application controls, allow/block/bypass/override decisions, custom rewrites, and clear evaluation traces. A policy change should be testable before broad deployment so an administrator can determine which clients and queries would be affected.

Beacon Shield should own DNS filtering and DNS-policy enforcement. Beacon Identity and GoreeCloud Identity should provide approved administrative and client identity context without making DNS resolution itself an authorization grant. Beacon Insights should provide privacy-aware query and policy visibility. Beacon API and Beacon Console should expose the same underlying first-party policy model rather than maintaining separate behavior. Beacon Horizon should own split-horizon, private-domain, network-context, and other DNS-routing decisions.

Policy and analytics features must remain local-first and privacy-governed. GoreeCloud DNS must not require a vendor-hosted analytics plane to provide profiles, filtering, logs, statistics, or administration. Raw query retention must be configurable and minimizable; operational statistics should prefer aggregate or privacy-preserving data when raw names are unnecessary. Privacy Shield requirements govern consent, minimization, retention, data control, and user-facing privacy behavior.

## Traffic-redirection boundary

DNS-level rewriting, CNAME/A/AAAA overrides, split-horizon answers, resolver routing, and response redirection may be implemented inside GoreeCloud DNS when protocol semantics, policy, and security permit them.

Transparent proxying, geographic egress selection, non-DNS traffic steering, or an Internet traffic-redirection network inspired by a reference service is not automatically a GoreeCloud DNS responsibility. Any such capability requires an explicit GoreeCloud Network architecture together with Wardveil Security and Privacy Shield review, independently defined authority boundaries, failure behavior, observability, user control, and production acceptance. GoreeCloud DNS must not silently become a general-purpose traffic proxy.

## Superset quality requirements

Feature count alone is insufficient. GoreeCloud DNS must aim to exceed the comparison products through:

### Security

Fail-safe defaults, no accidental open recursion, DNSSEC fail-closed handling, rebinding/private-address protection, strict listener and interface policy, least privilege, privilege separation where supported, bounded resource use, authenticated administration, auditable changes, dependency validation, secure backup/recovery, clear separation between DNS use and DNS administration, and Wardveil Security integration backed by executable evidence.

### Privacy

Local-first recursion, QNAME minimization where applicable, privacy-aware cache and statistics design, minimized and configurable query logging, retention and redaction controls, no product-analytics telemetry requirement, encrypted DNS, client-data minimization, user control, and explicit separation of operational observability from surveillance. Privacy claims must remain tied to implemented Privacy Shield controls and evidence.

### Control

One GoreeCloud-controlled configuration and runtime model, first-party APIs, transparent and explainable policy ownership, deterministic routing/failover, complete migration/export capability, no required external DNS backend or proprietary cloud service, documented recovery and rollback, GoreeCloud Identity integration, and integration with GoreeCloud Network without making DNS resolution equivalent to network authorization.

### Reliability, continuity, and performance

Sharded caches, bounded concurrency, prefetch/serve-stale/persistent caching, multiple resolver targets, latency-aware selection, independent cluster-node serving, runtime health statistics, graceful degradation, safe reloads, deterministic failure handling, Everkeep-aligned backup/recovery/portability, and production acceptance based on measured evidence rather than feature declarations.

### User experience

The Glaze UI administration experience should make powerful DNS policy understandable without hiding security or privacy consequences. Profiles, clients, queries, services, schedules, rewrites, upstreams, zones, DNSSEC state, health, analytics, privacy settings, and rule-decision explanations should use consistent terminology and accessible interaction patterns. A feature is not complete merely because an API or configuration field exists when the supported operator workflow requires a first-party interface.

## Competitive tracking

Comparison products may continue to evolve. GoreeCloud DNS should periodically review current stable releases and published capabilities of Technitium DNS Server, Pi-hole, AdGuard Home, NextDNS, and Control D and record material capabilities that expose a meaningful gap. A gap should be implemented when it is relevant to GoreeCloud's role, improves the platform, and does not add unnecessary complexity.

GoreeCloud DNS should not copy proprietary code, branding, control-plane architecture, or product-specific workflows merely to match a checklist. The objective is to provide the strongest coherent privacy-first, first-party DNS platform for GoreeCloud while meeting or exceeding the useful capability envelope of these reference products.

## Current implementation boundary

The current Beacon branch still does not satisfy this complete requirement and is not approved for production DNS migration.

Implemented source foundations now include the first-party Beacon request pipeline, sharded cache, resolver scheduling, classic UDP/TCP transport, iterative recursion, DNSSEC trust-chain validation, authenticated NSEC/NSEC3 denial, wildcard validation, scoped NSEC3 Opt-Out handling, RFC 9824 compact-denial handling, signed CNAME/DNAME alias-chain processing, out-of-bailiwick authoritative nameserver discovery, RFC 9156 QNAME minimisation, forward/conditional/stub and split-horizon resolver routing, runtime self-target protection, routed private DNSSEC trust anchors, and private child-delegation DNSSEC trust carry. The branch also contains migration-evidence and trust-anchor lifecycle work used to gate rehearsal eligibility.

Those foundations do not establish feature parity with the full target above. Production-required filtering and policy-profile parity, category/service controls, schedules, first-party policy decision tracing, complete authoritative DNS, encrypted downstream listeners and endpoint lifecycle, DHCP, clustering, full administration/API/identity workflows, privacy-aware analytics, Glaze UI completion, platform acceptance, exact-artifact runtime evidence, failure/restart testing, performance/security acceptance, backup/restore, rollback proof, and final migration authorization remain required as applicable.

Source declarations, tests, workflow definitions, and documentation do not authorize production cutover. Production migration remains blocked until the exact artifact passes the documented GoreeCloud DNS migration evidence and acceptance gates and an explicit cutover decision is recorded.