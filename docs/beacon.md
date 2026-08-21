# GoreeCloud Beacon

GoreeCloud Beacon is the official umbrella identity for the first-party capabilities of GoreeCloud DNS.

GoreeCloud DNS remains the application and service name. Beacon is the shared feature identity used to present the integrated DNS intelligence, resolution, security, routing, authoritative DNS, DHCP, observability, administration, automation, and extensibility capabilities that belong to GoreeCloud DNS.

## Purpose

Beacon represents the role of GoreeCloud DNS as trusted network guidance infrastructure: it helps approved clients discover services, resolve names, enforce DNS policy, identify safe destinations, publish authoritative information, maintain resilient resolution, and observe DNS health from one self-hosted platform.

Beacon does not create a separate daemon, backend, product dependency, or sidecar. Every Beacon capability is implemented inside GoreeCloud DNS and remains subject to the same configuration, security, privacy, access-control, observability, release, and production-acceptance requirements.

## Official relationship

- Product: GoreeCloud DNS
- Feature umbrella: GoreeCloud Beacon
- Design language: Glaze UI
- Security presentation and integration: Wardveil Security where applicable
- Privacy presentation and integration: Privacy Shield where applicable
- Runtime authority: GoreeCloud DNS

The preferred product phrasing is "GoreeCloud DNS with GoreeCloud Beacon" or simply "Beacon" when the GoreeCloud DNS context is already clear.

## Beacon capability families

Beacon covers the complete first-party DNS platform, including:

### Beacon Resolver

Recursive DNS, forwarding, conditional forwarding, stub resolution, concurrent resolution, latency-aware name-server selection, DNSSEC validation, QNAME minimization, resolver hardening, multiple-upstream failover, and encrypted forwarding.

### Beacon Cache

Positive caching, negative caching, aggressive negative caching, configurable TTL controls, serve-stale, prefetch, auto-prefetch, persistent cache state, cache sharding, cache statistics, and resilient recovery behavior.

### Beacon Zones

Authoritative DNS for internal and public zones, primary and secondary zones, forwarder and stub zones, local zones and local data, split-horizon DNS, zone transfer and notify, catalog-zone management, and DNSSEC signing.

### Beacon Shield

DNS-based advertisement, tracker, malware, phishing, telemetry, and unwanted-domain blocking; blocklists and allowlists; wildcard and regular-expression rules; response-policy zones; client-specific policy; subnet groups; query restrictions; private-address protection; and DNS-rebinding protection.

Beacon Shield is a DNS capability family. It does not replace Wardveil Security as GoreeCloud's broader security identity.

### Beacon Secure DNS

DNS-over-HTTPS, DNS-over-TLS, DNS-over-QUIC, encrypted forwarding, listener restrictions, certificate-aware encrypted DNS configuration, and secure transport policy.

### Beacon DHCP

Integrated DHCP address management, lease lifecycle, automatic DNS registration, and coordinated local DNS state.

### Beacon Horizon

Split-horizon processing, client/subnet/network-specific answers, private-domain routing, branch-office and VPN DNS behavior, hybrid-environment conditional forwarding, geolocation-aware responses where explicitly enabled, and DNS64 processing.

### Beacon Cluster

Multi-instance coordination, centralized management, configuration and zone synchronization, catalog-based provisioning, redundancy, health-aware operation, and controlled recovery across GoreeCloud DNS instances.

### Beacon Console

The Glaze UI browser administration experience for configuration, troubleshooting, query inspection, zone and policy management, DHCP administration, cluster management, health visibility, and operational control.

### Beacon API

The first-party HTTP API, scoped API tokens, scripting, orchestration, automation, integrations, configuration management, runtime administration, cache control, statistics retrieval, and external infrastructure interoperability.

### Beacon Identity

Multi-user administration, role-based access control, scoped permissions, API-token identity, TOTP two-factor authentication, OpenID Connect single sign-on, and administrative authorization boundaries.

### Beacon Insights

DNS query logging, privacy-aware auditing, statistics, health information, resolver behavior, upstream health, cache utilization, DNSSEC outcomes, authoritative-zone state, DHCP state, cluster status, metrics, and dashboards.

### Beacon Extensions

The controlled first-party processing framework for advanced blocking, split-horizon logic, DNS64, geolocation responses, forwarding logic, policy extensions, and custom DNS processing. Extensions must remain observable, permissioned, disableable, and unable to bypass core security or policy boundaries.

## Naming rules

Beacon is an umbrella identity, not a replacement for the GoreeCloud DNS product name. Feature-family names may be used in source documentation, Glaze UI navigation, settings, dashboards, release notes, APIs, and public-facing explanations when they improve clarity.

New Beacon family names should describe a durable capability domain rather than one implementation detail. They must not imply a separate executable service unless GoreeCloud DNS architecture explicitly establishes one. They should also avoid conflicting with existing GoreeCloud identities such as Glaze UI, Wardveil Security, Privacy Shield, Everkeep, Waypoint, or Quill.

## Architecture boundary

The target architecture remains one GoreeCloud DNS application/service. Beacon names organize first-party capability families inside that product. They do not restore the historical AdGuard Home plus Unbound split.

AdGuard Home remains only the maintained-fork starting point during the transition, and Unbound remains only a capability reference and migration source. The long-term runtime authority for Beacon features is GoreeCloud DNS itself.

## Production boundary

The Beacon identity may describe planned, partially implemented, or implemented first-party feature families, but naming does not constitute production acceptance. A Beacon capability may be described as production-ready only after its executable implementation has passed the applicable correctness, security, privacy, performance, recovery, migration, and runtime acceptance requirements.
