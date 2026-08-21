# GoreeCloud DNS First-Party Resolver Engine

GoreeCloud DNS is the complete DNS service. Its long-term architecture replaces both AdGuard Home and Unbound with one GoreeCloud-controlled application and runtime.

## Single-service architecture

Approved clients communicate only with GoreeCloud DNS. Filtering, policy enforcement, local/private DNS, recursive resolution, forwarding, caching, DNSSEC validation, resilience, privacy controls, statistics, and runtime administration are all first-party GoreeCloud DNS responsibilities.

There is no permanent Unbound backend boundary in the target architecture. Unbound is a capability reference and migration source only. AdGuard Home is the initial maintained-fork engineering foundation only. Neither remains a required production dependency after the GoreeCloud DNS native resolver transition is complete.

## Native resolver capabilities

The first-party resolver engine must provide:

- high-performance positive DNS caching;
- negative caching and aggressive DNSSEC negative caching;
- configurable minimum and maximum cache TTL controls;
- stale-cache serving during upstream degradation;
- prefetching of frequently requested records;
- recursive resolution and configurable forwarding modes;
- forward zones for selected namespaces;
- multiple upstream resolvers with health-aware redundancy and failover;
- DNSSEC validation and trust-anchor lifecycle management;
- query-name minimization where applicable;
- minimal DNS responses;
- local zones, local records, private service discovery, and custom overrides;
- response-policy zones and native DNS policy/filter integration;
- private-address and DNS-rebinding protection;
- client/network access-control policy;
- multi-threaded processing;
- partitioned/sharded caches that reduce worker contention;
- runtime statistics covering query volume, cache behavior, latency, failures, DNSSEC results, upstream health, stale answers, and resolver performance;
- authenticated runtime administration for reload, cache flush, statistics, upstream control, and resolver lifecycle management;
- interface restrictions, query restrictions, least-privilege operation, privilege separation where supported, and resolver hardening.

## Product boundary

The target request path is:

Approved Client -> GoreeCloud DNS listener -> client/access policy -> local/private DNS and policy evaluation -> cache -> recursive/forward resolver -> DNSSEC validation -> response policy -> client response

All stages remain inside the GoreeCloud DNS service and use one configuration, observability, administration, security, privacy, backup, and release lifecycle.

## Migration direction

The transition is incremental:

1. Preserve the inherited AdGuard Home behavior while GoreeCloud DNS stabilizes.
2. Introduce a native resolver subsystem behind explicit internal interfaces.
3. Implement and validate caching, recursion/forwarding, DNSSEC, resilience, privacy, and administration as GoreeCloud-owned capabilities.
4. Route GoreeCloud DNS query execution through the native resolver engine.
5. Migrate required configuration/state from the existing AdGuard Home and Unbound deployments.
6. Validate feature parity, performance, security, recovery, and rollback.
7. Retire the separate AdGuard Home and Unbound production services only after explicit acceptance.

The project must not claim that Unbound has already been replaced merely because these source contracts exist. Production replacement requires executable integration and target-environment acceptance.