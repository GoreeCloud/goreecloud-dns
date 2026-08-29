# GoreeCloud Beacon

GoreeCloud Beacon is the official first-party feature umbrella for GoreeCloud DNS. Beacon is not a separate executable, daemon, backend, or sidecar. All Beacon capabilities remain inside the single GoreeCloud DNS application and runtime.

The current development branch contains an isolated GoreeCloud-owned native DNS core under `internal/gcdns`. Existing AdGuard Home and Unbound runtime behavior remains unchanged until GoreeCloud DNS completes implementation, exact-artifact validation, migration rehearsal, rollback proof, platform acceptance, and explicit production cutover authorization.

## Feature families

- **Beacon Resolver** — recursive resolution, DNSSEC validation, resolver routing, private recursion, QNAME minimisation, upstream target selection, and DNS transport.
- **Beacon Cache** — first-party caching, negative caching, serve-stale, persistence, prefetch, and cache observability.
- **Beacon Zones** — authoritative and locally administered DNS zones.
- **Beacon Shield** — DNS filtering, policy profiles, category/service controls, custom rules, schedules, family policy, and DNS rewrites.
- **Beacon Secure DNS** — encrypted DNS listeners, forwarding transports, and endpoint lifecycle.
- **Beacon DHCP** — address allocation and DNS registration where enabled.
- **Beacon Horizon** — split-horizon, private namespace, network-context, and routing policy.
- **Beacon Cluster** — multi-instance coordination and synchronization.
- **Beacon Console** — first-party DNS administration user experience.
- **Beacon API** — automation and administrative APIs.
- **Beacon Identity** — DNS-administration and approved client identity integration with GoreeCloud Identity.
- **Beacon Insights** — privacy-aware DNS and policy observability, aggregate statistics, diagnostics, and health.
- **Beacon Extensions** — controlled first-party extension points and future processing capabilities.

Beacon Shield is a DNS capability family and does not replace Wardveil Security as GoreeCloud's wider protection, detection, trust, verification, and response system. Privacy-sensitive Beacon behavior remains subject to Privacy Shield. Continuity, backup, recovery, preservation, portability, and succession remain subject to Everkeep. User-facing administration remains subject to the current Stable Glaze UI requirements.

## Native request path

The native Beacon request path is organized around explicit first-party contracts for policy, authoritative resolution, caching, recursive/forwarded resolution, DNSSEC state, observation, downstream presentation, and error handling. Security-sensitive behavior is designed to fail closed rather than infer trust from incomplete evidence.

The current isolated source path includes normalized request/result contracts and explicit DNSSEC trust states; deterministic policy → authority → cache → resolver pipeline ordering; sharded concurrency-safe cache behavior; bounded resolver target scheduling and classic UDP/TCP transport; iterative root/delegation recursion; DNSSEC trust-chain validation; authenticated NSEC/NSEC3 denial; scoped NSEC3 Opt-Out; wildcard proofs; RFC 9824 compact denial; signed CNAME/DNAME validation; out-of-bailiwick authoritative nameserver discovery; RFC 9156 QNAME minimisation; forward/conditional/stub/split-horizon routing; runtime self-target protection; private routed DNSSEC trust anchors and child-delegation trust carry; protected trust-anchor lifecycle and migration evidence; and a first-party Beacon Policy Profiles implementation.

`ValidatingForwardingResolver` is Beacon Resolver's locally validating forwarding path. Configured recursive forwarders supply DNS data with RD/DO/CD semantics, but Beacon ignores upstream AD as trust evidence and performs root-anchored DNSSEC authentication locally before returning secure state. Raw forwarding remains explicitly DNSSEC-indeterminate unless this validation wrapper is selected.

### RFC 9824 Compact Denial of Existence

Beacon Resolver implements RFC 9824 Compact Denial of Existence using authenticated `NXNAME` proof material. Compact Answers OK is treated as a hop-by-hop capability: validating resolver components may request and consume it upstream, while downstream presentation is reconstructed from the authenticated semantic result rather than blindly copying a client's EDNS option through the resolver path. Cached compact-denial metadata preserves the authenticated conclusion without mutating shared cache state for a particular client's DO/CO presentation.

### CNAME/DNAME alias chains

Beacon Resolver implements bounded CNAME/DNAME alias chains with validation of each ordinary CNAME RRset, signed DNAME handling, and RFC 6672 synthesized CNAME checks. A synthesized CNAME is accepted only when the securely validated DNAME derives the same target and the synthesis obeys the expected signature and TTL boundary. Detected alias cycles, conflicting alias data, malformed substitutions, or an indeterminate/bogus DNSSEC hop fail closed. Unresolved alias targets are resolved through a fresh applicable resolver/trust path instead of inheriting unrelated zone trust across the alias boundary.

### Out-of-bailiwick authoritative nameserver discovery

Out-of-bailiwick authoritative nameserver discovery is request-scoped and bounded. Beacon trusts direct A/AAAA glue only when it is in-bailiwick for the delegated child; external advertised nameserver hostnames are resolved through the same applicable resolver mode and successful discovered addresses are cached only inside the current top-level resolution. Active discovery cycles, missing mandatory in-domain glue, malformed address data, and discovery-budget exhaustion fail closed.

### Beacon Resolver Routing

Beacon Resolver Routing uses longest-suffix namespace selection for recursive, forward, and stub behavior, with explicit client/network split-horizon selection where configured. Runtime validation prevents configured or dynamically discovered resolver targets from pointing back to active GoreeCloud DNS listeners. Forwarding sets RD as required by the forward path, while stub authority processing preserves its separate terminal-authoritative boundary; routed aliases reselect the applicable route rather than inheriting an unrelated route indefinitely.

### Beacon Routed Private DNSSEC Trust Anchors

Beacon Routed Private DNSSEC Trust Anchors allow an explicitly configured private signed namespace to establish local DNSSEC trust without relying on an upstream AD bit. `PrivateTrustAnchorResolver` authenticates the configured apex DNSKEY trust anchor and terminal data locally. `ValidatingDelegatingStubResolver` carries authenticated parent trust through signed private child delegations and can perform an authenticated insecure transition only when signed NSEC/NSEC3 evidence proves DS absence; unproven children fail closed before trust is inferred. Raw forwarded and ordinary stub responses clear `AD` and remain `DNSSECIndeterminate`. `ValidatingForwardingResolver` is the separate root-anchored locally validating forwarding path for recursive forwarders.

## Beacon Policy Profiles

`internal/gcdns/policy_profiles.go` provides the first executable Beacon Shield profile engine through the native `Policy` boundary. Exact client identity assignments take precedence over network assignments; network assignments use longest-prefix matching; all other requests use the explicit default profile. Rule evaluation is deterministic and independent of input-array ordering.

The source model supports exact-domain, suffix, locally defined category, and locally defined service selectors; explicit priorities; timezone-aware schedules including overnight windows; allow, NXDOMAIN/REFUSED block, A/AAAA/ANY address rewrite, and CNAME rewrite outcomes; configuration collision checks; and DNSSEC-indeterminate classification for synthetic policy answers.

`internal/gcdns/policy_stats.go` supplies a concurrency-safe Beacon Insights aggregate recorder keyed only by profile, rule, action, assignment scope, and match kind. It intentionally does not store queried names, client addresses, client identifiers, or matched domain/catalog values. Raw query retention is a separate Privacy Shield-governed observability capability and is not enabled merely to produce policy statistics.

`docs/policy-profiles.md` records implementation, platform, privacy, validation, and production boundaries. `scripts/validate_policy_profiles.py` is wired into the existing `beacon-native-core` lint job before `go test ./internal/gcdns` and protects the policy engine, tests, aggregate statistics, Beacon identity documentation, competitive requirement, and GoreeCloud platform boundary markers.

NextDNS and Control D are reference/inspiration products for applicable policy-control capability. Beacon does not depend on their hosted control planes or proprietary implementations, and the existence of this initial engine is not a claim of complete feature parity.

## Beacon NSEC3 Authenticated Denial

Beacon includes source-level NSEC3 authenticated denial for exact-name NODATA, conservative NXDOMAIN proof, and authenticated secure-to-insecure delegation transitions. NSEC3 proof material must use consistent supported parameters, remain within the authenticated zone, and validate cryptographically with trusted DNSKEY state.

Scoped NSEC3 Opt-Out support is limited to standards-backed insecure-delegation transitions. Generic terminal denial and wildcard proof paths do not treat Opt-Out coverage as sufficient evidence.

## Migration and production boundary

Beacon source code, tests, validators, CI definitions, documentation, migration evidence, and successful isolated runs are necessary evidence but do not transfer production DNS authority. Production migration requires the exact runtime artifact to satisfy the documented resolver, filtering/policy, DNSSEC, listener, encrypted-DNS, authoritative, DHCP, cluster, API/identity, security, privacy, continuity, Glaze UI, failure, backup/restore, rollback, performance, and operational acceptance gates that apply to the approved migration scope.

Current production DNS listeners, AdGuard Home, Unbound, Network/NetBird DNS assignment, filtering, DHCP, authoritative DNS, encrypted DNS endpoints, Caddy, firewall state, client DNS behavior, credentials, private zones, forwarding/stub targets, and trust-anchor state remain unchanged unless a separately evidenced and explicitly authorized migration changes them.
