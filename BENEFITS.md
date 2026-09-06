# GoreeCloud DNS — Benefits

This file describes the value GoreeCloud DNS is designed to provide while keeping current source progress separate from future production claims.

## Privacy and ownership

- Moves DNS intelligence, filtering, resolution, policy, administration, and observability toward a first-party GoreeCloud-controlled platform.
- Reduces permanent dependence on external DNS products and proprietary cloud DNS services.
- Uses privacy-aware logging and avoids making analytics telemetry a requirement.
- Supports local-first resolution principles and QNAME minimization where applicable.

## Security

- Establishes fail-safe defaults that do not permit accidental public open recursion.
- Separates DNS-client serving from administrative access and keeps administration loopback-restricted by default in the source configuration model.
- Enables DNSSEC validation by default in the safe configuration model and treats rebinding protection as a core safeguard.
- Keeps encrypted DNS, authoritative publication, DHCP, clustering, and extensions disabled until deliberately configured.
- Requires controlled extensions to remain inside security, privacy, policy, resource, and observability boundaries.

## Reliability and resilience

- First-party cache work includes persistent state safety, stale-policy handling, prefetch selection, and controlled recovery behavior.
- Resolver scheduling is designed for bounded concurrency, timeouts, failover, cancellation, and latency-aware target selection.
- The clustering direction requires individual DNS nodes to remain capable of serving independently rather than making a central controller a single point of DNS failure.
- Backup, recovery, migration, and deterministic failover are product requirements rather than optional operational afterthoughts.

## Administrative control

- GoreeCloud Beacon provides one coherent feature system for recursive DNS, authoritative DNS, filtering, encrypted transport, DHCP, horizon logic, clustering, administration, identity, observability, APIs, and extensions.
- First-party APIs and Glaze UI administration are intended to make advanced DNS control understandable without requiring a collection of permanent external sidecars.
- Client, subnet, group, role, token, and policy concepts provide a path toward granular administration rather than one global configuration for every user and device.

## Network-wide protection

- The product direction combines resolver capability with network-wide unwanted-domain filtering for advertisements, trackers, malware, phishing, telemetry, and other policy-defined domains.
- Advanced rule and policy goals include blocklists, allowlists, wildcards, regular expressions, response policies, and per-client/subnet behavior.
- Integration with GoreeCloud Network is designed to provide consistent private DNS and network-aware policy without collapsing the two products into one service.

## Independence and long-term maintainability

- The fork-to-native strategy lets GoreeCloud use mature open-source behavior during transition while progressively owning the capabilities that define the DNS product.
- Core DNS architecture is documented as explicit internal subsystems, making ownership, testing, security review, migration, and future replacement clearer.
- The competitive target is broader than ad blocking alone: GoreeCloud DNS is intended to supersede the combined roles currently filled by filtering, recursive, authoritative, encrypted-DNS, DHCP, and DNS-administration tools where doing so is technically justified.

## User benefit

The long-term benefit is a single private, secure, resilient, self-hosted DNS platform with strong filtering, deep administrative control, dependable resolution, transparent recovery, and no requirement to surrender DNS policy or operational visibility to an outside provider.
