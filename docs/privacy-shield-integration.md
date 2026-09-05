# GoreeCloud DNS Privacy Shield Integration

## Purpose

GoreeCloud DNS is an enforcement adapter for the `dns-privacy` capability of GoreeCloud Privacy Shield.

This integration gives Privacy Shield a platform-level way to identify and report DNS privacy protection without turning Privacy Shield into the DNS server and without changing the existing GoreeCloud DNS/Unbound authority boundary.

## Authority boundary

GoreeCloud DNS remains authoritative for client-facing DNS filtering, DNS policy enforcement, private service discovery, client policy, allow/block decisions, and the DNS-facing runtime behavior inherited from and maintained on the AdGuard Home foundation.

Unbound remains authoritative for recursive resolution, caching, and DNSSEC validation under the current approved GoreeCloud DNS architecture.

Privacy Shield provides the shared privacy identity, adapter contract, capability vocabulary, and privacy-safe status contract. It does not directly answer DNS queries, modify filter rules, control Unbound, or replace GoreeCloud DNS administration.

Wardveil Security remains the separate platform-wide security/protection presentation identity and does not become the authority for DNS privacy filtering.

## Declared capability

The initial adapter declares only:

- `dns-privacy`

The adapter does **not** declare Browser capabilities such as `content-blocking`, `tracking-resistance`, or `url-cleaning`; networking capabilities such as `network-privacy`; or broader application capabilities such as telemetry, retention, deletion, or portable-export controls merely because GoreeCloud DNS may have related settings.

A capability may be added only after GoreeCloud DNS implements and validates that specific Privacy Shield contract.

## What `dns-privacy` means here

Within GoreeCloud DNS, `dns-privacy` covers the DNS-layer privacy role already inherent in the project's documented client-facing filtering and policy responsibilities. Examples may include approved advertisement/tracker domain filtering, policy-based DNS blocking, privacy-oriented client policy, and private DNS service discovery where those behaviors are actually enabled and accepted in the target runtime.

The declaration does not claim that DNS filtering prevents all tracking. It does not substitute for Browser request interception, URL parameter cleaning, application data minimization, VPN/private-network transport, or endpoint security.

## Privacy-safe status boundary

A future runtime status producer may report high-level Privacy Shield DNS state, but it must not export raw DNS queries or other private activity merely to render a central Privacy Shield, Manager, or Wardveil status surface.

A status record must contain only minimized state necessary to explain the adapter's declared capability and acceptance state. The producer must explicitly declare that:

- raw private activity is not included;
- credentials are not included;
- identifying content is not included;
- runtime acceptance remains required;
- production approval is not inferred.

Query logs, client identifiers, source addresses, requested domain names, rule-match details, authentication material, configuration secrets, private rewrites, and unrestricted diagnostic logs remain within the authoritative DNS environment unless a separately approved workflow genuinely requires them.

## Acceptance boundary

`privacy-shield/adapter.json` records `production_approved=false`.

This is deliberate. The adapter declaration documents the intended and source-supported capability boundary; it does not approve the current GoreeCloud DNS development branch, inherited AdGuard Home runtime, future isolated deployment, or production migration.

Before `production_approved` may become true, the exact GoreeCloud DNS runtime intended for production must demonstrate the declared DNS privacy behavior, fail-closed configuration handling, privacy-safe status output if enabled, migration/rollback safety, and compatibility with the approved DNS architecture.

Shared Privacy Shield contract validation is not runtime acceptance.

## Current implementation state

The current work is a source-level adapter foundation layered on the active GoreeCloud DNS stable-fork development branch. It does not modify the DNS engine, filter engine, query-processing path, DNS configuration, production AdGuard Home instance, Unbound, client DNS settings, Caddy, NetBird, firewall rules, DHCP behavior, or production cutover state.

The next runtime step is to design and validate a minimized DNS Privacy Shield status producer against an isolated GoreeCloud DNS build. Until that producer and runtime acceptance exist, Manager and Wardveil should treat DNS Privacy Shield runtime status as unavailable rather than synthesize it from DNS logs or configuration.
