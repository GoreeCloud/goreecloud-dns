# GoreeCloud DNS First-Party DNS Platform

GoreeCloud DNS is the complete DNS service. Its long-term architecture replaces both AdGuard Home and Unbound with one GoreeCloud-controlled application and runtime.

## Single-service architecture

Approved clients communicate only with GoreeCloud DNS. Recursive resolution, authoritative DNS, encrypted DNS, filtering, DHCP, local/private DNS, forwarding, caching, DNSSEC, clustering, administration, automation, observability, and extensible DNS processing are first-party GoreeCloud DNS responsibilities.

There is no permanent Unbound backend boundary in the target architecture. Unbound is a capability reference and migration source only. AdGuard Home is the initial maintained-fork engineering foundation only. Neither remains a required production dependency after the GoreeCloud DNS native transition is complete.

## Recursive, authoritative, and zone services

GoreeCloud DNS will provide a full recursive resolver for direct root-to-authority resolution and controlled forwarding; authoritative DNS hosting for internal and public zones; primary, secondary, forwarder, and stub zones; catalog-based zone provisioning; zone transfer and notification; split-horizon answers based on client, subnet, or network identity; and conditional forwarding for private namespaces, directories, VPNs, branch offices, hybrid environments, and other internal DNS systems.

DNSSEC is a native responsibility in both directions: recursive responses are validated, while authoritative zones can be signed and have signing state managed by GoreeCloud DNS.

## Filtering and security policy

The DNS policy engine will provide network-wide advertisement, tracker, malware, phishing, telemetry, and unwanted-domain blocking using blocklists, allowlists, wildcard rules, regular expressions, response-policy zones, client-specific rules, subnet groups, and other native policy sources. Rebinding protection, interface/query restrictions, least-privilege operation, access controls, DNSSEC, and resolver hardening remain part of the same service security boundary.

## Encrypted DNS

The service will accept encrypted client DNS through DNS-over-HTTPS, DNS-over-TLS, and DNS-over-QUIC. It will also support authenticated encrypted forwarding to compatible upstream resolvers when forwarding is selected instead of full recursion.

## Performance and resilience

Caching includes positive, negative, aggressive negative, persistent, serve-stale, prefetch, auto-prefetch, configurable TTL controls, and sharded/partitioned caches. The resolver will support concurrent recursive work, health-aware multi-upstream failover, latency-based name-server selection, and multi-threaded request processing.

## DHCP and dynamic DNS

An integrated DHCP server will share the GoreeCloud DNS configuration and policy model. DHCP leases may automatically register and maintain approved DNS records so address allocation, naming, client identity, and policy can remain synchronized.

## Administration, identity, and automation

GoreeCloud DNS will provide a browser-based administration console and comprehensive HTTP API. Administration will support multiple users, role-based access control, scoped API tokens, TOTP two-factor authentication, and OIDC single sign-on. Runtime controls will include safe configuration reload, cache management, statistics, zone operations, upstream/resolver management, service health, and other approved administrative actions.

## Clustering and high availability

Multiple GoreeCloud DNS instances may form a managed cluster with centrally coordinated configuration, zone/catalog synchronization, health state, and operational control while retaining independent DNS-serving capability for redundancy and scale. Cluster design must avoid turning the control plane into a mandatory single point of DNS failure.

## Observability

The service will provide detailed query logging, audit logging, resolver and authoritative statistics, cache metrics, DNSSEC outcomes, forwarding and recursion health, latency, failures, DHCP state, dashboards, health information, and metrics suitable for GoreeCloud Monitor and other approved systems. Privacy controls must minimize or disable sensitive query retention when detailed logs are not operationally required.

## Extensible processing framework

The DNS request pipeline will expose controlled first-party extension points for advanced blocking, split-horizon processing, geolocation-based responses, DNS64, rebinding protection, advanced forwarding, and custom DNS processing logic. Extensions must execute inside defined policy, security, privacy, resource, and observability boundaries rather than bypassing the core DNS engine.

## Product request path

A representative request path is:

Approved Client -> GoreeCloud DNS listener (DNS/DoH/DoT/DoQ) -> identity/access policy -> split-horizon/local/authoritative evaluation -> filtering and custom processing -> cache -> recursive/forward/stub resolution -> DNSSEC validation -> response policy -> client response

Authoritative queries may terminate at the authoritative zone stage. DHCP, clustering, administration, API, metrics, auditing, and extension management are supporting first-party subsystems of the same product.

## Migration direction

The transition remains incremental:

1. Preserve inherited AdGuard Home behavior while GoreeCloud DNS stabilizes.
2. Introduce native internal interfaces for resolver, authoritative, policy, encrypted-DNS, DHCP, identity, API, observability, and cluster subsystems.
3. Replace inherited or external behavior capability-by-capability with GoreeCloud-owned implementations.
4. Route production query and management paths through the native subsystems after executable validation.
5. Migrate required configuration and state from current AdGuard Home and Unbound deployments.
6. Validate feature parity, DNS correctness, DNSSEC, security, privacy, performance, high availability, failure recovery, backup/restore, migration, and rollback.
7. Retire the separate AdGuard Home and Unbound production services only after explicit acceptance.

The source capability contract is an implementation requirement, not evidence that every subsystem is already complete. Production replacement requires executable integration and target-environment acceptance.
