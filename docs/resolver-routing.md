# Beacon Resolver Routing

GoreeCloud Beacon implements the first native forward, conditional, stub, and split-horizon resolver-routing stage in `internal/gcdns/routing.go`.

## Pipeline position

Routing remains a resolver responsibility. The native pipeline continues to execute policy, authoritative data, and cache lookup before calling the configured `Resolver`. A `RoutingResolver` then selects direct recursion, forwarding, or a stub resolver for the current question.

This preserves the existing distinction between local/authoritative answers and resolver routing. Routing does not grant network authorization and does not replace DNS policy.

## Namespace selection

Each `ResolverRoute` has a DNS suffix and one of three modes:

- `recursive` — use the default native recursive resolver;
- `forward` — send the full question to configured recursive upstream targets;
- `stub` — send the full question non-recursively to explicitly configured authoritative targets for the routed zone.

The router uses longest DNS-suffix matching. An explicit recursive route can therefore override a broader forwarding rule. A root (`.`) forwarding route can implement normal forwarding while narrower recursive, conditional-forwarding, or stub routes remain more specific.

Ambiguous route definitions fail closed. Route names must be unique, forward/stub routes require a resolver, and recursive routes cannot silently substitute another resolver for the configured default.

## Split-horizon scope

A route may be unscoped or limited by `ClientID`, client IP prefixes, or both. For routes with the same namespace suffix, matching specificity is:

1. exact client identity;
2. longest matching client IP prefix;
3. unscoped namespace route.

A more-specific DNS namespace always outranks a less-specific namespace before client-scope specificity is considered. This supports conditional namespace routing and first-stage split-horizon behavior for client and subnet contexts without creating a second DNS pipeline.

GoreeCloud Network/VLAN/group identity is not yet copied into the native `Request` contract. This stage therefore uses the already normalized client identity and address fields. Future Network integration may add explicit group or segment selectors only through authenticated, minimal context contracts.

## Cache isolation

The in-memory cache remains conservatively client-partitioned. Its key now contains both `ClientID` and `ClientIP` rather than preferring identity and discarding the address. This prevents an otherwise stable client identity from reusing a split-horizon cache entry after moving to another network address or subnet.

This conservative partition is intentionally narrower than a future route-aware shared-cache model. Route configuration changes, Network identity scopes, and explicitly shareable split-horizon views require their own cache-scope lifecycle before cache sharing can be broadened safely.

## Forwarding

`ForwardingResolver` uses the existing `TargetScheduler` for bounded target failover. Upstream queries set RD=1 and continue to request DNSSEC material through EDNS/DO. SERVFAIL, REFUSED, FORMERR, NOTIMP, and other non-NOERROR/NXDOMAIN responses are treated as target failures so another configured forward target can be attempted.

Forwarded responses do not inherit DNSSEC trust from the upstream `AD` bit. Beacon clears `AD` and records `DNSSECIndeterminate` because this stage does not yet contain a local validating-forwarder implementation. This is a source-development boundary, not permission to treat unvalidated forwarded data as secure.

Encrypted forwarding is not part of this classic-DNS source slice. It will use the same route-selection model when approved DoT, DoH, and DoQ upstream transports are implemented.

## Stub resolution

`StubResolver` sends RD=0 to explicitly configured authoritative targets and uses the scheduler for target failover. A target must return a terminal authoritative NOERROR or NXDOMAIN response. Non-authoritative responses, referrals, and retryable error codes are rejected for this first stub stage.

The router can continue an alias chain after a stub answer. If a stub response ends in CNAME/DNAME redirection, the alias target is routed again using its own namespace and client scope, so a private stub alias may transition to normal recursion or another route without inheriting the previous route's trust state.

Subdelegation walking below a stub zone is deliberately staged. The first stub implementation does not reinterpret an authority referral as a terminal answer.

## Loop, ambiguity, and runtime self-target controls

A request carries an internal route-execution context. If a route resolver re-enters the same named route before the previous execution has completed, Beacon fails with a resolver-route-loop error. Alias loops remain covered by the existing bounded alias engine.

`internal/gcdns/routing_runtime_validation.go` adds deterministic runtime self-target validation for classic forward and stub routes. `ValidateRoutingRuntime` receives the active GoreeCloud DNS listener endpoints, a startup snapshot of local interface addresses, and the configured native routes. It does not perform DNS resolution or interface discovery itself.

The validator rejects an exact target/listener address and port match. An unspecified wildcard listener such as `0.0.0.0:53` or `[::]:53` rejects same-family targets on that port when the target is loopback or appears in the supplied local-address snapshot. An external resolver on the same port remains valid, and a local address on a different port remains a distinct service boundary.

Runtime self-target validation requires numeric IP target addresses. A hostname target cannot be proven non-self without a separate approved bootstrap-resolution lifecycle and therefore fails this startup check. Unspecified target addresses and malformed listener or local-address state also fail closed.

The startup integrator is responsible for supplying the complete active listener set and the relevant local-address snapshot. Addresses hidden behind NAT, external VIPs, VRFs, container namespaces, or other network indirection cannot be inferred by this network-free validator unless they are represented in that startup state. Production eligibility therefore still requires runtime integration tests against the actual GoreeCloud DNS listener environment.

## DNSSEC boundary

Direct recursion can continue to use the existing `ValidatingIterativeResolver`. Forward and stub transports in this stage return `DNSSECIndeterminate`; they do not bypass or impersonate local DNSSEC validation. Alias chains that cross routed resolvers combine DNSSEC state conservatively, so an indeterminate routed hop cannot be promoted by a later secure hop.

Local DNSSEC validation for forwarded or stub data, authenticated-upstream policy, and trust-anchor behavior for private stub namespaces remain separate implementation stages.

## Production boundary

`RoutingResolver`, `ForwardingResolver`, `StubResolver`, and runtime self-target validation remain inside the isolated `internal/gcdns` development path. No production AdGuard Home, Unbound, NetBird/GoreeCloud Network nameserver assignment, client DNS setting, forwarding target, Caddy rule, firewall rule, DHCP behavior, or production cutover is changed by this source milestone.
