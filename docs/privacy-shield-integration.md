# GoreeCloud DNS Privacy Shield Integration

## Purpose

GoreeCloud DNS is an enforcement adapter for the `dns-privacy` capability of GoreeCloud Privacy Shield.

This integration gives Privacy Shield a platform-level way to identify and present DNS privacy protection without turning Privacy Shield into the DNS server, filter engine, resolver, policy authority, or configuration authority.

## Authority boundary

GoreeCloud DNS remains the authoritative GoreeCloud product for client-facing DNS service, DNS filtering and policy, private service discovery, resolver/forwarder selection, query administration, and the migration toward the first-party Beacon DNS request path.

The current repository still contains an AdGuard Home-derived compatibility data plane, and deployed environments may continue using configured external recursive/forwarding components during migration. Those components are transitional implementation/deployment details; this adapter does not make them permanent GoreeCloud architecture and does not transfer DNS authority to Privacy Shield.

Privacy Shield provides the shared privacy identity, adapter contract, capability vocabulary, and privacy-safe status contract. It does not directly answer DNS queries, modify DNS filter rules, select upstreams, control recursion, or replace GoreeCloud DNS administration.

Wardveil Security remains the separate platform security/protection authority. GoreeCloud Manager may consume minimized operational state but does not become the DNS runtime or privacy enforcement boundary.

## Declared capability

The initial adapter declares only:

- `dns-privacy`

The adapter does not declare Browser capabilities such as `content-blocking`, `tracking-resistance`, or `url-cleaning`; networking capabilities such as `network-privacy`; or broader application capabilities such as telemetry, retention, deletion, portable export, or generic privacy status merely because GoreeCloud DNS may have related settings.

A capability may be added only after GoreeCloud DNS implements and validates that specific current Privacy Shield contract.

## What `dns-privacy` means here

Within GoreeCloud DNS, `dns-privacy` covers privacy-oriented DNS filtering or policy behavior at the authoritative DNS runtime without exporting raw DNS activity for centralized status. Examples may include approved advertisement/tracker domain filtering, policy-based DNS blocking, privacy-oriented client policy, and private DNS service discovery where those behaviors are actually enabled and accepted in the target runtime.

The declaration does not claim that DNS filtering prevents all tracking. It does not substitute for Browser request interception, URL parameter cleaning, application data minimization, VPN/private-network transport, endpoint security, or Wardveil Security controls.

## Privacy-safe status boundary

A runtime status producer may report high-level Privacy Shield DNS state only through the current Privacy Shield status contract. It must not export raw DNS queries or other private activity merely to render a central Privacy Shield, Manager, or Wardveil surface.

Privacy Shield status must remain a separate contract from GoreeCloud Infrastructure Status. Shared runtime evidence may be projected into both contracts, but the envelopes and state vocabularies must not be conflated.

A Privacy Shield DNS status record must contain only minimized state necessary to explain the adapter's declared capability and acceptance state. It must explicitly preserve these invariants:

- raw private activity is not included;
- credentials are not included;
- identifiers are not included;
- runtime acceptance remains required;
- production approval is not inferred.

Query logs, client identifiers, source addresses, requested domain names, rule-match details, authentication material, configuration secrets, private rewrites, filter contents, certificate/private-key material, and unrestricted diagnostic logs remain within the authoritative DNS environment unless a separately approved workflow genuinely requires them.

## Acceptance boundary

`privacy-shield/adapter.json` records `production_approved=false` and `runtime_acceptance_required=true`.

This is deliberate. The adapter declaration documents the intended and source-supported capability boundary; it does not approve the current GoreeCloud DNS development branch, the inherited compatibility data plane, any native Beacon development branch, an isolated deployment, or a production migration.

Before `production_approved` may become true, the exact GoreeCloud DNS runtime intended for production must demonstrate the declared DNS privacy behavior, fail-closed configuration handling, a schema-valid privacy-minimized status projection if status is enabled, migration/rollback safety, and target-environment acceptance.

Shared Privacy Shield contract validation is not runtime acceptance.

## Current implementation state

The current work is a source-level adapter foundation layered on the active GoreeCloud DNS development foundation. It does not modify the DNS engine, filter engine, query-processing path, resolver/forwarder configuration, client DNS settings, DHCP behavior, firewall state, credentials, production listeners, or cutover state.

A separate GoreeCloud Infrastructure Status development line already defines coarse DNS runtime evidence and an atomic local status handoff. That evidence source is suitable for reuse, but its Infrastructure Status v1 envelope is not the Privacy Shield status contract. The next Privacy Shield runtime slice is therefore to project only the necessary coarse DNS privacy evidence into a distinct schema-valid Privacy Shield status record while keeping `production_approved=false` until runtime acceptance is complete.

## Canonical contract checkpoint

This adapter shape was rechecked against the current GoreeCloud Privacy Shield adapter schema and `dns-privacy` capability registry on the Privacy Shield `main` line during the September 7, 2026 reconciliation. Future Privacy Shield contract changes still require fresh consumer review; this document does not freeze an external contract revision indefinitely.
