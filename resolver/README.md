# GoreeCloud DNS Resolver Backend

This directory defines the first-party recursive, caching, and forwarding resolver backend used behind the client-facing GoreeCloud DNS policy layer.

## Role boundary

GoreeCloud DNS / AdGuard Home remains responsible for downstream client handling, filtering, policy enforcement, client-aware controls, query-log presentation, and private DNS rewrites. The resolver backend is responsible for recursive/cached resolution, forwarding policy, DNSSEC validation, stale-cache resilience, privacy minimization, negative caching, resolver hardening, and resolver statistics/administration.

The default configuration binds only to loopback on port 5353. A production deployment must explicitly approve any different bind interface, network exposure, firewall rule, or container/network topology.

## Implemented resolver capabilities

The checked-in Unbound configuration establishes source-controlled defaults and extension points for:

- positive and negative DNS caching;
- configurable minimum and maximum TTLs;
- aggressive NSEC/NSEC3 negative caching;
- DNSSEC validation using an automatically maintained root trust anchor;
- stale-cache serving when upstream resolution is unavailable or slow;
- prefetching of frequently used records and DNSSEC keys;
- query-name minimization;
- minimal DNS responses;
- configurable forward zones and multiple forward addresses;
- local zones, local data, and private-domain exceptions;
- DNS-rebinding/private-address protections;
- optional Response Policy Zones (RPZ);
- multi-threaded processing and power-of-two cache slabs to reduce contention;
- bounded socket/EDNS behavior;
- extended runtime statistics;
- local certificate-authenticated `unbound-control` administration;
- loopback-only resolver and control interfaces by default;
- allow/refuse client ACLs;
- identity/version hiding and resolver hardening.

## Runtime administration

The intended administrative surface is `unbound-control` over the loopback control channel. Supported operational actions include configuration reload, cache flushes, statistics retrieval/reset, status inspection, local-zone management, and controlled resolver lifecycle actions supported by Unbound.

Administrative access must not be exposed as a public network service. Production automation should execute through the approved host/container administration boundary and should record only the minimum operational data needed for troubleshooting and performance analysis.

## Forwarding and recursion

The repository configuration intentionally does not embed a production upstream DNS provider. Deployment-specific configuration must choose one of the following explicitly:

1. recursive resolution through root/authoritative DNS; or
2. one or more approved upstream forwarders, optionally scoped to selected domain zones.

When multiple upstream resolvers are configured for a forward zone, they provide redundancy and availability. Forward-zone decisions must be documented and must not silently bypass GoreeCloud DNS filtering or privacy policy.

## Local DNS and RPZ

`local-zones.conf` is the repository contract for internal authoritative DNS data and private-domain exceptions. Production addresses and internal records belong in deployment-controlled configuration rather than this public repository when they would disclose private infrastructure details.

`rpz.conf` defines the supported RPZ integration point. RPZ is disabled until an approved feed or locally maintained policy zone exists. RPZ must complement, not ambiguously duplicate, the client-facing GoreeCloud DNS filtering policy.

## Validation and production status

These files establish the source-controlled resolver foundation only. They do not indicate that a production Unbound instance has been upgraded, reconfigured, migrated, or accepted. Production acceptance requires isolated configuration validation, DNSSEC tests, cache/stale-cache tests, failover tests, ACL and rebinding tests, performance/load tests, runtime statistics verification, administrative-control verification, and rollback/recovery evidence on the target environment.
