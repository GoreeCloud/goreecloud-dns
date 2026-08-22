# GoreeCloud DNS Competitive Superset Requirement

GoreeCloud DNS is intended to become a first-party DNS platform that supersedes Technitium DNS Server, Pi-hole, and AdGuard Home in overall capability, security, privacy, and operator control. This is a product target and acceptance requirement, not a claim that the current development branch already exceeds those products.

## Governing rule

A future stable GoreeCloud DNS release should not require an administrator to deploy Technitium DNS Server, Pi-hole, AdGuard Home, or Unbound to obtain a major DNS capability that fits the documented GoreeCloud DNS role. Where those products expose mature capabilities, Beacon should provide an equivalent or stronger first-party implementation when the capability is applicable to GoreeCloud.

## Capability bar

Beacon must cover the combined useful capability envelope of the comparison products, including:

- recursive resolution, caching, DNSSEC validation, forwarding, conditional forwarding, concurrency, health-aware and latency-aware resolution;
- authoritative primary/secondary/stub/forwarder zones, catalog zones, AXFR/IXFR, NOTIFY, DNSSEC signing, NSEC/NSEC3, and secure transfer options;
- network-wide ad, tracker, malware, phishing, telemetry, service, and custom-domain filtering with allowlists, blocklists, wildcards, regular expressions, client/subnet/group policy, RPZ, and SafeSearch/family policy;
- DoH, DoT, DoQ, HTTP/3 where appropriate, encrypted forwarding, and explicit transport policy;
- integrated DHCP and DNS registration;
- split horizon, geolocation-aware responses, DNS64, advanced forwarding and controlled processing extensions;
- clustering, centralized multi-node management, configuration/zone/policy synchronization, independent node serving, health visibility, and deterministic failover;
- browser administration, REST/HTTP API, automation, runtime controls, query tools, statistics, dashboards, logs, metrics, backup/recovery, and troubleshooting;
- multi-user administration, RBAC, scoped API tokens, TOTP, OIDC SSO, auditable administration, and least-privilege access;
- extensibility comparable to DNS application/plugin systems, but with explicit privilege, resource, privacy, observability, and disable boundaries.

## Superset quality requirements

Feature count alone is insufficient. GoreeCloud DNS must aim to exceed the comparison products through:

### Security

Fail-safe defaults, no accidental open recursion, DNSSEC fail-closed handling, rebinding/private-address protection, strict listener and interface policy, least privilege, privilege separation where supported, bounded resource use, authenticated administration, auditable changes, dependency validation, secure backup/recovery, and clear separation between DNS use and DNS administration.

### Privacy

Local-first recursion, QNAME minimization where applicable, privacy-aware cache and statistics design, minimized and configurable query logging, retention controls, no product-analytics telemetry requirement, encrypted DNS, client-data minimization, and explicit separation of operational observability from surveillance.

### Control

One GoreeCloud-controlled configuration and runtime model, first-party APIs, transparent policy ownership, deterministic routing/failover, complete migration/export capability, no required external DNS backend or proprietary cloud service, documented recovery and rollback, and integration with GoreeCloud Network without making DNS resolution equivalent to network authorization.

### Reliability and performance

Sharded caches, bounded concurrency, prefetch/serve-stale/persistent caching, multiple resolver targets, latency-aware selection, independent cluster-node serving, runtime health statistics, graceful degradation, safe reloads, deterministic failure handling, and production acceptance based on measured evidence rather than feature declarations.

## Competitive tracking

Comparison products may continue to evolve. GoreeCloud DNS should periodically review current stable releases of Technitium DNS Server, Pi-hole, and AdGuard Home and record material capabilities that expose a meaningful gap. A gap should be implemented when it is relevant to GoreeCloud's role, improves the platform, and does not add unnecessary complexity.

GoreeCloud DNS should not copy features merely to match a checklist. The objective is to provide the strongest coherent privacy-first self-hosted DNS platform for GoreeCloud while meeting or exceeding the useful capability envelope of these reference products.

## Current implementation boundary

The current Beacon branch does not yet satisfy this complete requirement. Native cache, resolver scheduling, classic transport, iterative recursion, DNSSEC trust-chain carry, positive terminal-answer validation, conservative signed-NSEC proof for intentionally unsigned delegations, propagation of authenticated `DNSSECInsecure` state, and exact-owner signed-NSEC NODATA proof are now under active development in source.

Complete NSEC NXDOMAIN closest-encloser and wildcard proof, NSEC3 authenticated denial, signed alias handling, out-of-bailiwick nameserver discovery, QNAME minimization, authoritative DNS, full filtering, encrypted listeners, DHCP, clustering, APIs, identity, observability, extensions, and Glaze UI administration remain staged until implemented and validated.
