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

The current isolated source path includes:

- normalized request/result contracts and explicit DNSSEC trust states;
- deterministic policy → authority → cache → resolver pipeline ordering;
- sharded concurrency-safe cache behavior;
- bounded resolver target scheduling and classic UDP/TCP transport;
- iterative root/delegation recursion;
- DNSSEC trust-chain validation, authenticated NSEC/NSEC3 denial, scoped NSEC3 Opt-Out, wildcard proofs, RFC 9824 compact denial, and signed CNAME/DNAME validation;
- out-of-bailiwick authoritative nameserver discovery;
- RFC 9156 QNAME minimisation;
- forward, conditional, stub, and split-horizon routing;
- runtime self-target protection;
- private routed DNSSEC trust anchors and signed child-delegation trust carry;
- protected trust-anchor lifecycle, activation/recovery evidence, persistence, and audit reconciliation;
- migration evidence contracts that cannot authorize production cutover by themselves; and
- a first-party Beacon Policy Profiles implementation for reusable client/network profiles, deterministic assignments and rule precedence, category/service matching, schedules, allow/block/rewrite actions, privacy-minimized decision tracing, and privacy-safe aggregate policy counters.

## Beacon Policy Profiles

`internal/gcdns/policy_profiles.go` now provides the first executable Beacon Shield profile engine through the native `Policy` boundary. Exact client identity assignments take precedence over network assignments; network assignments use longest-prefix matching; all other requests use the explicit default profile. Rule evaluation is deterministic and independent of input-array ordering.

The source model supports exact-domain, suffix, locally defined category, and locally defined service selectors; explicit priorities; timezone-aware schedules including overnight windows; allow, NXDOMAIN/REFUSED block, A/AAAA/ANY address rewrite, and CNAME rewrite outcomes; configuration collision checks; and DNSSEC-indeterminate classification for synthetic policy answers.

`internal/gcdns/policy_stats.go` supplies a concurrency-safe Beacon Insights aggregate recorder keyed only by profile, rule, action, assignment scope, and match kind. It intentionally does not store queried names, client addresses, client identifiers, or matched domain/catalog values. Raw query retention is a separate Privacy Shield-governed observability capability and is not enabled merely to produce policy statistics.

`docs/policy-profiles.md` records the implementation and privacy boundary, and `scripts/validate_policy_profiles.py` is wired into the existing `beacon-native-core` lint job before `go test ./internal/gcdns`.

NextDNS and Control D are reference/inspiration products for applicable policy-control capability. Beacon does not depend on their hosted control planes or proprietary implementations, and the existence of this initial engine is not a claim of complete feature parity.

## Beacon NSEC3 Authenticated Denial

Beacon includes source-level NSEC3 authenticated denial for exact-name NODATA, conservative NXDOMAIN proof, and authenticated secure-to-insecure delegation transitions. NSEC3 proof material must use consistent supported parameters, remain within the authenticated zone, and validate cryptographically with trusted DNSKEY state.

Scoped NSEC3 Opt-Out support is limited to standards-backed insecure-delegation transitions. Generic terminal denial and wildcard proof paths do not treat Opt-Out coverage as sufficient evidence.

## Migration and production boundary

Beacon source code, tests, validators, CI definitions, documentation, migration evidence, and successful isolated runs are necessary evidence but do not transfer production DNS authority. Production migration requires the exact runtime artifact to satisfy the documented resolver, filtering/policy, DNSSEC, listener, encrypted-DNS, authoritative, DHCP, cluster, API/identity, security, privacy, continuity, Glaze UI, failure, backup/restore, rollback, performance, and operational acceptance gates that apply to the approved migration scope.

Current production DNS listeners, AdGuard Home, Unbound, Network/NetBird DNS assignment, filtering, DHCP, authoritative DNS, encrypted DNS endpoints, Caddy, firewall state, client DNS behavior, credentials, private zones, forwarding/stub targets, and trust-anchor state remain unchanged unless a separately evidenced and explicitly authorized migration changes them.
