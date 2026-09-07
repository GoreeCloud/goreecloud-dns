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

The adapter declares only `dns-privacy`.

It does not declare Browser capabilities such as `content-blocking`, `tracking-resistance`, or `url-cleaning`; networking capabilities such as `network-privacy`; or broader application capabilities such as telemetry, retention, deletion, portable export, or generic privacy status merely because GoreeCloud DNS may have related settings.

A capability may be added only after GoreeCloud DNS implements and validates that specific current Privacy Shield contract.

## What `dns-privacy` means here

Within GoreeCloud DNS, `dns-privacy` covers privacy-oriented DNS filtering or policy behavior at the authoritative DNS runtime without exporting raw DNS activity for centralized status. Examples may include approved advertisement/tracker domain filtering, policy-based DNS blocking, privacy-oriented client policy, and private DNS service discovery where those behaviors are actually enabled and accepted in the target runtime.

The declaration does not claim that DNS filtering prevents all tracking. It does not substitute for Browser request interception, URL parameter cleaning, application data minimization, VPN/private-network transport, endpoint security, or Wardveil Security controls.

## Privacy-safe status boundary

The runtime-status development line projects only the existing coarse DNS lifecycle evidence into the current Privacy Shield status v1 shape. It must not export raw DNS queries or other private activity merely to render a central Privacy Shield, Manager, or Wardveil surface.

The Infrastructure Status v1 envelope is not the Privacy Shield status contract. Privacy Shield status remains a separate contract from GoreeCloud Infrastructure Status. Shared runtime evidence may feed both contracts, but their envelopes, environment variables, and state vocabularies are distinct.

Privacy Shield status uses `GOREECLOUD_DNS_PRIVACY_SHIELD_STATUS_FILE`. Infrastructure Status uses `GOREECLOUD_DNS_STATUS_FILE`. Neither local handoff is enabled unless its own path is explicitly configured.

The Privacy Shield DNS status record contains only minimized state and explicitly preserves these invariants:

- raw private activity is not included;
- credentials are not included;
- identifiers are not included;
- runtime acceptance remains required;
- production approval is false.

Query logs, client identifiers, source addresses, requested domain names, rule-match details, authentication material, configuration secrets, private rewrites, filter contents, certificate/private-key material, and unrestricted diagnostic logs remain within the authoritative DNS environment unless a separately approved workflow genuinely requires them.

## Acceptance boundary

`privacy-shield/adapter.json` records `production_approved=false` and `runtime_acceptance_required=true`.

The runtime producer uses adapter id `dns`, product `GoreeCloud DNS`, runtime authority `GoreeCloud/goreecloud-dns`, and adapter contract version `1`.

The runtime mapper preserves that boundary. Healthy resolver/filtering/policy evidence produces `development` / `pending-acceptance`, not `protected` / `active`. Resolver loss fails closed to `unavailable`; incomplete filtering or policy evidence reports `attention` / `inactive`.

Before `production_approved` may become true, the exact GoreeCloud DNS runtime intended for production must demonstrate the declared DNS privacy behavior, fail-closed configuration handling, schema-valid privacy-minimized status output where enabled, migration/rollback safety, and target-environment acceptance.

Shared Privacy Shield contract validation is not runtime acceptance.

## Current implementation state

This branch contains:

- the `dns-privacy` adapter declaration;
- a fail-closed adapter validator;
- an exact reviewed Privacy Shield contract lock;
- a separate Privacy Shield runtime-status serializer and atomic writer;
- tests for state mapping, privacy minimization, permissions, and empty-path rejection;
- a local publisher integration that reuses coarse DNS runtime evidence while keeping Infrastructure Status and Privacy Shield output separate;
- a dedicated fail-closed runtime-status source validator in lint CI.

The implementation does not modify the DNS engine, filter engine, query-processing path, resolver/forwarder configuration, client DNS settings, DHCP behavior, firewall state, credentials, production listeners, or cutover state.

This remains Development source work. The status output itself is not proof that the declared privacy capability has passed runtime acceptance.

## Canonical contract checkpoint

The adapter and runtime projection were checked against GoreeCloud Privacy Shield `main` revision `f10d90c0c53c0b876d6ff5cdb6926d6b87205438` on September 7, 2026. Exact reviewed schema/capability blob identities are recorded in `privacy-shield/status-contract.lock.json`.

Future Privacy Shield contract changes require fresh consumer review. The lock is an evidence anchor, not a permanent exemption from current-contract adoption.
