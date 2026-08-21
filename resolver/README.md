# GoreeCloud DNS First-Party DNS Platform

GoreeCloud DNS is the complete DNS service. Its long-term architecture replaces both AdGuard Home and Unbound with one GoreeCloud-controlled application and runtime.

## GoreeCloud Beacon

**GoreeCloud Beacon** is the official umbrella identity for the first-party capabilities of GoreeCloud DNS. GoreeCloud DNS remains the application and service name; Beacon provides the shared feature identity for the integrated resolution, authoritative DNS, security, filtering, caching, encrypted DNS, DHCP, clustering, administration, identity, observability, automation, and extensibility capabilities inside the single GoreeCloud DNS runtime.

The canonical Beacon feature-family definitions and naming boundaries are documented in `docs/beacon.md`.

## Single-service architecture

Approved clients communicate only with GoreeCloud DNS. Filtering, policy enforcement, local/private DNS, recursive resolution, authoritative DNS, encrypted DNS, forwarding, caching, DNSSEC, DHCP, clustering, identity, observability, APIs, administration, and extensibility are all first-party GoreeCloud DNS responsibilities.

There is no permanent Unbound backend boundary in the target architecture. Unbound is a capability reference and migration source only. AdGuard Home is the initial maintained-fork engineering foundation only. Neither remains a required production dependency after the GoreeCloud DNS native transition is complete.

## Integrated capability areas

### Recursive and forwarding engine

The native resolver provides full recursive DNS resolution, concurrent recursion, latency-based name-server selection, DNSSEC validation and trust-anchor management, QNAME minimization, minimal responses, conditional forwarding, forward zones, encrypted forwarding, multiple-upstream failover, and compatibility with private and hybrid DNS infrastructures.

### Authoritative DNS

GoreeCloud DNS provides authoritative DNS hosting for internal and public zones, including primary, secondary, forwarder, and stub zones; zone transfer and notify; catalog-based zone provisioning and synchronization; and DNSSEC signing for authoritative zones.

### Cache and resilience

The cache layer provides positive, negative, and aggressive-negative caching, configurable TTL controls, serve-stale, prefetch, auto-prefetch, persistent caching, and sharded cache structures designed to reduce contention while preserving predictable recovery behavior.

### Filtering and policy

The filtering engine provides network-wide advertisement, tracker, malware, phishing, telemetry, and unwanted-domain blocking with blocklists, allowlists, wildcard rules, regular expressions, response-policy zones, client-specific policies, subnet-based groups, split-horizon evaluation, and DNS rebinding protection.

### Encrypted DNS

The listener layer supports DNS-over-HTTPS, DNS-over-TLS, and DNS-over-QUIC. Encrypted forwarding is independently configurable for compatible upstream resolvers. Encrypted listeners are opt-in in the example configuration so TLS/QUIC material and exposure cannot be enabled accidentally.

### DHCP and dynamic DNS

The integrated DHCP server provides address assignment and automatic DNS record registration so managed leases and local DNS state can share a first-party lifecycle.

### Identity and administration

The administration plane provides a browser-based Glaze UI console and comprehensive HTTP API. Identity capabilities include multi-user administration, role-based access control, scoped API tokens, TOTP two-factor authentication, and OpenID Connect single sign-on.

### Clustering and availability

A managed cluster can centrally coordinate multiple GoreeCloud DNS instances, synchronize approved configuration and zone state, and support redundant deployments. Clustering is disabled by default until explicit node identity, trust, synchronization, failure, and recovery configuration is supplied.

### Observability

First-party observability includes detailed query logging, audit logging, runtime statistics, dashboards, health information, metrics, resolver/upstream health, cache behavior, DNSSEC outcomes, authoritative-zone state, DHCP state, and cluster status. Privacy-sensitive query data remains subject to GoreeCloud privacy and retention controls.

### Extensible processing framework

The Extensible processing framework supports controlled additions for advanced blocking, split-horizon processing, geolocation-based responses, DNS64, advanced forwarding, and custom DNS processing. Extensions must not bypass policy enforcement, gain secret access without an explicit grant, or operate without observability and disable controls.

## Native subsystem ownership

`resolver/subsystems.json` is the source-controlled internal-boundary contract. It divides the single product into coordinated first-party subsystems for listeners, identity/policy, the query pipeline, filtering, authoritative DNS, caching, recursive resolution, DHCP, clustering, administration, observability, configuration, runtime security, and extensions.

These subsystem boundaries exist for maintainability and testing; they do not create external sidecar services or restore an AdGuard Home/Unbound split.

## Executable native core foundation

`internal/gcdns` is the first executable GoreeCloud-owned DNS core package introduced during the fork-to-native transition. It currently establishes normalized request/result types and first-party interfaces for policy evaluation, authoritative resolution, caching, recursive/forward resolution, and privacy-aware observation.

`internal/gcdns/pipeline.go` implements the initial deterministic native path: policy -> authoritative DNS -> cache -> recursive/forward resolver. This package is deliberately not connected to the inherited production request path yet. It exists so native behavior can be built, unit-tested, and accepted independently before traffic is migrated.

`internal/gcdns/config.go` introduces typed security-sensitive configuration validation. The initial invariants reject missing listeners, disabled DNSSEC validation, disabled rebinding protection, missing recursive ACLs, unrestricted recursive ACLs when public recursion is disabled, and unrestricted administrative networks.

The `native-dns-core` CI job executes `go test ./internal/gcdns`, while the architecture validator also requires the native core files and pipeline stage markers. This converts part of the DNS platform plan from documentation-only contracts into compilable first-party Go code without changing production behavior.

## Native cache implementation

`internal/gcdns/cache.go` provides the first substantive GoreeCloud-owned runtime subsystem. It implements sharded concurrency-safe in-memory caching, bounded capacity, TTL expiration and wire-TTL aging, serve-stale, positive and negative caching, defensive DNS message copies, client-aware cache partitioning, cache statistics, and flush serialization.

`internal/gcdns/cache_persistence.go` adds opt-in persistent cache snapshots. Persistent state is versioned, stores packed DNS messages rather than process-specific objects, is written through an owner-only temporary file and atomic rename, and restores only entries that remain usable under the active cache policy. Persistence paths are explicitly supplied by configuration or runtime management; no repository path or production state location is assumed. Persistent state remains ordinary runtime cache data rather than source-controlled configuration and must follow GoreeCloud data-protection, permission, backup, and privacy requirements.

`internal/gcdns/cache_prefetch.go` adds first-party prefetch and auto-prefetch selection primitives. Popularity is tracked from successful fresh-cache hits. Entries become refresh candidates only after a configurable hit threshold and when their remaining positive TTL enters a configurable refresh window. Candidate generation does not itself contact the network; the native resolver scheduler owns controlled refresh execution through the normal pipeline so prefetch cannot bypass policy, DNSSEC, forwarding, observability, or cancellation behavior.

Persistent cache and prefetch are therefore native GoreeCloud DNS capabilities, not external daemons or Unbound dependencies. Their deterministic tests cover persistence round trips, owner-only persistence permissions, expiry rejection, schema-version rejection, popular-entry selection, cold-entry exclusion, and prefetch state flushing in addition to the existing cache TTL, stale, negative, partitioning, capacity, and concurrency tests.

## Beacon Resolver scheduler

`internal/gcdns/resolver_scheduler.go` provides bounded concurrent target execution, per-attempt deadlines, first-valid-result cancellation, failure fallback, latency-aware target ordering, caller cancellation propagation, and privacy-safe success/failure/latency accounting. `ResolveTargets` extends the same scheduler behavior to delegation-specific target sets, allowing iterative recursion to change authoritative servers at each hop without duplicating concurrency or timeout logic.

`internal/gcdns/prefetch_runner.go` executes Beacon Cache proactive refresh candidates through a complete request resolver such as the native pipeline rather than contacting a network target directly. This preserves the normal policy, authority, cache, resolver, DNSSEC, observability, and cancellation boundaries.

## Beacon Resolver classic DNS transport

`internal/gcdns/resolver_transport.go` is the first classic DNS transport implementation. It performs context-bound DNS exchanges over UDP or TCP, validates response identity and question equivalence, detects UDP truncation, and can retry through TCP when explicitly enabled. Truncated UDP responses fail closed when fallback is disabled, and truncated TCP responses are rejected.

The classic DNS transport is intentionally separate from Beacon Secure DNS. DoT, DoH, and DoQ require their own certificate, endpoint, policy, and exposure controls and are not silently treated as ordinary UDP/TCP resolver targets.

## Beacon Resolver iterative delegation walker

`internal/gcdns/iterative_resolver.go` adds the first native recursive delegation walker. It starts from an approved root/bootstrap target set, disables the recursion-desired bit for authoritative queries, follows NS referrals, accepts A/AAAA in-bailiwick glue, changes target sets through the shared scheduler, derives positive or RFC-style SOA-bounded negative cache lifetimes, and stops on bounded depth or repeated delegation state.

`internal/gcdns/root_hints.go` contains a built-in bootstrap set derived from the IANA root-server registry reviewed on August 21, 2026. IPv4 and IPv6 addresses are represented independently so Beacon Insights can eventually retain address-specific health and latency information. A future runtime root-hints lifecycle must support controlled refresh and validation rather than assuming the compiled list is permanent.

Referral processing is deliberately conservative. Additional-section addresses are accepted only when they correspond to an advertised NS name and that NS name is inside the delegated zone. Out-of-bailiwick glue is ignored rather than trusted. Referrals with no usable in-bailiwick glue currently fail closed because recursive address discovery for out-of-bailiwick name servers is not implemented yet.

This iterative foundation is not a production-complete recursive resolver. DNSSEC chain validation and root trust anchors, DS/DNSKEY processing, out-of-bailiwick NS address discovery, CNAME/DNAME chasing, QNAME minimization, lame-delegation handling, EDNS policy, richer retry policy, and production runtime integration remain required before production acceptance.

## Configuration model

`resolver/config.example.json` is the safe configuration-model baseline. It intentionally defaults to:

- recursive access from loopback networks only;
- `public_recursive_resolver: false`;
- DNSSEC validation enabled;
- DNS rebinding protection enabled;
- DoH, DoT, and DoQ listeners disabled until explicitly configured;
- authoritative serving disabled until zones are explicitly provisioned;
- DHCP disabled until scopes are explicitly configured;
- clustering disabled until node trust and peers are explicitly configured;
- extensions disabled until modules are explicitly approved;
- administration/API binding on loopback by default;
- production approval remaining false.

Public authoritative DNS is a separate exposure class from public recursive DNS. A public authoritative zone may be intentionally served without ever allowing unrestricted recursive resolution.

## Target request path

Approved Client -> GoreeCloud DNS listener (DNS/DoH/DoT/DoQ) -> identity/access policy -> split-horizon/local/authoritative evaluation -> filtering/custom processing -> cache -> recursive/forward/stub resolution -> DNSSEC validation -> response policy -> client response

Authoritative queries can terminate at the authoritative stage. DHCP, clustering, administration, auditing, metrics, configuration, and extension management are supporting first-party subsystems of the same GoreeCloud DNS product.

## Migration direction

The transition is incremental:

1. Preserve inherited AdGuard Home behavior while GoreeCloud DNS stabilizes.
2. Establish explicit internal subsystem interfaces and a GoreeCloud-owned configuration model.
3. Implement and validate the native resolver, cache, authoritative, filtering, encrypted-DNS, DHCP, identity, cluster, observability, and extension subsystems incrementally.
4. Route production-equivalent query execution through native GoreeCloud DNS paths as each subsystem passes isolated acceptance.
5. Migrate required configuration and state from existing AdGuard Home and Unbound deployments.
6. Validate feature parity, correctness, DNSSEC behavior, authoritative serving/signing, filtering, DHCP, encrypted DNS, performance, privacy, security, high availability, recovery, and rollback.
7. Retire the separate AdGuard Home and Unbound production services only after explicit production acceptance.

The project must not claim that AdGuard Home or Unbound has already been replaced merely because these source contracts exist. Production replacement requires executable integration and target-environment acceptance.
