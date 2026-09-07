# GoreeCloud DNS — Competitive Objectives

This record defines the DNS products and capability areas GoreeCloud DNS uses as benchmarks for continuous improvement. It is a product and acceptance target, not a claim that every listed capability is currently implemented or production-accepted.

## Primary benchmark products

- Technitium DNS Server
- AdGuard Home
- Pi-hole
- Unbound
- Comparable authoritative, recursive, filtering, encrypted-DNS, and self-hosted DNS platforms where they establish a stronger capability bar

## Capability bar to match or exceed

- Full recursive resolution and forwarding
- Authoritative DNS for internal and public zones
- DNSSEC validation and authoritative signing
- NSEC and NSEC3 authenticated denial
- Primary, secondary, stub, forwarder, local, and catalog zones
- AXFR, IXFR, NOTIFY, and secure zone-transfer workflows
- Concurrent recursive resolution, failover, latency-aware selection, and resilient caching
- Positive, negative, aggressive-negative, persistent, serve-stale, prefetch, and auto-prefetch caching
- Network-wide advertisement, tracker, malware, phishing, telemetry, and unwanted-domain blocking
- Blocklists, allowlists, wildcard rules, regular expressions, response-policy behavior, client/subnet/group policy, and SafeSearch/family controls
- DNS over HTTPS, DNS over TLS, DNS over QUIC, and encrypted forwarding
- DHCP and automatic local DNS registration
- Split-horizon, network-specific, geolocation-aware, conditional, and DNS64 behavior where approved
- Multi-node clustering and independent node serving
- Glaze UI web administration, first-party APIs, automation, runtime controls, dashboards, logs, metrics, and diagnostics
- Multi-user RBAC, scoped API tokens, TOTP, and OIDC SSO
- Controlled extensions without bypassing core DNS safeguards

## Objectives GoreeCloud DNS should exceed

- No accidental open recursion and fail-safe defaults
- Privacy-aware local-first resolution and QNAME minimization where applicable
- Minimized and configurable query logging with no required analytics telemetry
- Strict separation between DNS-client service and DNS administration
- Deterministic failover and independently serving cluster nodes
- First-party configuration, APIs, resolver, cache, policy, authoritative, administration, and observability ownership
- Complete backup, recovery, export, migration, and rollback control
- Deep but bounded integration with GoreeCloud Network and the wider GoreeCloud Suite
- No permanent dependency on Technitium DNS Server, Pi-hole, AdGuard Home, Unbound, or proprietary cloud DNS for capabilities that belong inside GoreeCloud DNS

## Capabilities intentionally rejected

- Public recursive-resolver exposure by default
- Required vendor cloud control planes
- Mandatory telemetry or analytics
- Extensions that can bypass DNS security, privacy, policy, resource, or observability boundaries
- Permanent sidecar architecture for core DNS capabilities that GoreeCloud DNS is intended to own
- Feature parity that adds complexity without meaningful GoreeCloud value

## Competitive review rule

Current stable releases of benchmark products should be reviewed periodically. A newly identified gap becomes a GoreeCloud objective only when it materially improves DNS security, privacy, reliability, control, interoperability, administration, recovery, or user experience.
