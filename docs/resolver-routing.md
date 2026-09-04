# Beacon Resolver Routing

GoreeCloud Beacon implements native forward, conditional, stub, and split-horizon resolver routing in `internal/gcdns` while keeping routing after policy, authoritative data, and cache lookup.

## Pipeline position

Routing remains a resolver responsibility. The native pipeline continues to execute policy, authoritative data, and cache lookup before calling the configured `Resolver`. A `RoutingResolver` then selects direct recursion, forwarding, or a stub resolver for the current question.

This preserves the existing distinction between local/authoritative answers and resolver routing. Routing does not grant network authorization and does not replace DNS policy.

## Namespace selection

Each `ResolverRoute` has a DNS suffix and one of three modes:

- `recursive` — use the default native recursive resolver;
- `forward` — send the full question to configured recursive upstream targets;
- `stub` — send the question non-recursively to explicitly configured authoritative targets for the routed zone.

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

The in-memory cache remains conservatively client-partitioned. Its key contains both `ClientID` and `ClientIP`. This prevents an otherwise stable client identity from reusing a split-horizon cache entry after moving to another network address or subnet.

This conservative partition is intentionally narrower than a future route-aware shared-cache model. Route configuration changes, Network identity scopes, and explicitly shareable split-horizon views require their own cache-scope lifecycle before cache sharing can be broadened safely.

## Forwarding

`ForwardingResolver` uses the existing `TargetScheduler` for bounded target failover. Upstream queries set RD=1 and request DNSSEC material through EDNS/DO. SERVFAIL, REFUSED, FORMERR, NOTIMP, and other non-NOERROR/NXDOMAIN responses are treated as target failures so another configured forward target can be attempted.

Raw forwarded responses do not inherit DNSSEC trust from the upstream `AD` bit. `ForwardingResolver` clears `AD` and records `DNSSECIndeterminate` because a route transport alone is not local DNSSEC validation evidence.

`ValidatingForwardingResolver` is the locally validating forward variant. It uses the same recursive target scheduler but forces CD on validation traffic, ignores AD, authenticates the root DNSKEY RRset from Beacon's root DS trust anchors, authenticates DS-to-DNSKEY transitions to the response signer zone, validates terminal data locally, and returns `DNSSECSecure` only when the complete supported trust path succeeds.

A signed forwarded response identifies its authoritative signer zone through RRSIG Signer Name. Beacon walks trust to that signer zone instead of probing DS at ordinary signed owner names. If a candidate between the current authenticated zone and a deeper signer zone is not a delegation, Beacon requires an authenticated exact-name NSEC or non-Opt-Out NSEC3 DS-NODATA proof before continuing with the same parent keys.

If authenticated denial proves a real delegation has no DS, the forwarding trust state becomes `DNSSECInsecure` and does not silently recover below that boundary. A missing DS alone is never sufficient. A DS state that cannot be authenticated as a secure delegation, an insecure delegation, or a supported non-delegation fails closed.

Client DS queries preserve parent-side semantics: the terminal DS RRset is validated with authenticated parent keys instead of crossing into the child first.

Recursive forwarders may return complete CNAME/DNAME chains spanning multiple zones. The validating forwarder isolates and validates the current alias link, then issues a fresh locally validating forwarded query for the target rather than validating target-zone data with source-zone keys. The existing 16-hop alias bound and weakest-link DNSSEC combination remain active.

Configured validating-forwarder endpoints are exposed to runtime self-target validation exactly like raw forwarder endpoints. A validation wrapper therefore cannot hide a forward target that points back into an active GoreeCloud DNS listener.

The detailed locally validating forwarding boundary is in `docs/validating-forwarding.md`.

Encrypted forwarding is not part of this classic-DNS source slice. Approved DoT, DoH, and DoQ forwarding transports will use the same routing and local-validation separation when implemented.

## Stub resolution

`StubResolver` remains the strict terminal-only stub implementation. It sends RD=0 to explicitly configured authoritative targets, uses scheduler failover, and requires terminal authoritative NOERROR or NXDOMAIN. It rejects referrals rather than silently treating them as final data.

`internal/gcdns/stub_subdelegation.go` adds `DelegatingStubResolver` for namespaces that legitimately contain delegated children. It starts from the configured stub-zone authorities and follows only referrals that are strictly closer to the requested name and remain below the configured stub zone. Referral walking is capped at 16 delegation transitions. Blank stub zones are rejected before FQDN normalization.

The subdelegation path reuses Beacon's conservative referral planner. Direct A/AAAA glue is accepted only for an advertised NS hostname inside the delegated child. Required in-domain glue remains fail-closed. Sibling NS Additional-section addresses are not trusted as glue. When a sibling NS hostname is still inside the configured stub namespace, Beacon may resolve its A/AAAA address through the same stub namespace and then continue the child delegation.

A nameserver hostname outside the configured stub namespace is not resolved through public Internet recursion by this stage. If no other usable authoritative target exists, the stub referral fails. This keeps private stub resolution from leaking internal delegation infrastructure into an unrelated recursive path and prevents an external dependency from being introduced implicitly.

Every ordinary subdelegation target receives RD=0. Terminal data must be authoritative. Referral responses must parse as usable, closer delegations before they can change the authority set. AD is cleared and the ordinary `DelegatingStubResolver` result remains `DNSSECIndeterminate`; transport walking alone does not create DNSSEC trust.

`ValidatingDelegatingStubResolver` adds an explicit local DNSSEC-validation variant for a stub namespace whose apex has an out-of-band configured DNSKEY trust anchor. It preserves the same namespace, 16-referral, glue, sibling-discovery, and external-NS restrictions while authenticating signed and deliberately unsigned child delegations locally.

The router can continue an alias chain after a stub answer. If a validated stub response ends in CNAME/DNAME redirection, the alias RRset's current trust state is preserved and the alias target is routed again using its own namespace and client scope. A target outside the private route therefore does not inherit the private anchor automatically.

## Loop, ambiguity, and runtime self-target controls

A request carries an internal route-execution context. If a route resolver re-enters the same named route before the previous execution has completed, Beacon fails with a resolver-route-loop error. Alias loops remain covered by the existing bounded alias engine. Delegating stub referrals must move strictly closer to the QNAME and are also bounded by the 16-transition stub depth limit.

`internal/gcdns/routing_runtime_validation.go` adds deterministic runtime self-target validation for classic forward and stub routes. `ValidateRoutingRuntime` receives the active GoreeCloud DNS listener endpoints, a startup snapshot of local interface addresses, and the configured native routes. It does not perform DNS resolution or interface discovery itself.

`NewRuntimeValidatedRoutingResolver` combines ordinary route-graph validation with runtime listener/target validation and is the intended construction boundary once the native listener runtime supplies its actual endpoint state. Both `DelegatingStubResolver` and `ValidatingDelegatingStubResolver` are cloned into the returned route graph with the same immutable listener boundary attached.

The validator rejects an exact target/listener address and port match. An unspecified wildcard listener such as `0.0.0.0:53` or `[::]:53` rejects same-family targets on that port when the target is loopback or appears in the supplied local-address snapshot. An external resolver on the same port remains valid, and a local address on a different port remains a distinct service boundary.

The attached boundary is also applied after every ordinary or validating delegating-stub referral. Newly discovered child-authority endpoints are checked before the next DNS exchange, so a safe configured stub root cannot redirect the resolver back into a local GoreeCloud DNS listener through glue or an internally resolved sibling nameserver address.

Runtime self-target validation requires numeric IP target addresses. A hostname target cannot be proven non-self without a separate approved bootstrap-resolution lifecycle and therefore fails this startup check. Unspecified target addresses and malformed listener or local-address state also fail closed.

The startup integrator is responsible for supplying the complete active listener set and the relevant local-address snapshot. Addresses hidden behind NAT, external VIPs, VRFs, container namespaces, or other network indirection cannot be inferred by this network-free validator unless they are represented in that startup state. Production eligibility therefore still requires runtime integration tests against the actual GoreeCloud DNS listener environment.

Resolver wrappers do not create a bypass. Runtime endpoint discovery unwraps `PrivateTrustAnchorResolver` and `ValidatingForwardingResolver`; runtime construction recursively clones private trust-anchor wrappers when necessary so a wrapped delegating stub still receives the active listener boundary for dynamically discovered referral targets.

## DNSSEC boundary

Direct recursion can use `ValidatingIterativeResolver`. Raw forward, terminal-only stub, and ordinary delegating-stub transports return `DNSSECIndeterminate`; they do not impersonate local validation.

`ValidatingForwardingResolver` now supplies root-anchored local validation for ordinary Internet forwarding without trusting upstream AD. It returns `DNSSECSecure` only after its local root/DS/DNSKEY/terminal validation succeeds, or `DNSSECInsecure` after an authenticated insecure-delegation transition. Unsupported or unproven trust states fail closed.

`PrivateTrustAnchorResolver` provides local terminal validation for a configured private or otherwise locally administered signed namespace when the answer is authenticated by the anchored apex keyset. The configured DNSKEY trust anchor must be obtained out of band, must belong to the exact routed zone, and must authenticate the complete apex DNSKEY RRset before Beacon trusts the returned apex keyset.

`ValidatingDelegatingStubResolver` extends that private trust through child delegations. For a signed child, the parent-authenticated DS RRset must lead to a child DNSKEY that authenticates the complete child apex DNSKEY RRset before child keys are carried forward. If authenticated denial instead proves DS absence, the branch becomes `DNSSECInsecure`, child DNSKEY acquisition is skipped, and deeper referrals cannot restore secure trust without another explicit anchor.

Alias chains that cross routed resolvers combine DNSSEC state conservatively. An insecure hop makes the completed determinate chain insecure; bogus or indeterminate secure-branch data cannot be hidden by a later secure hop.

The routed trust boundaries are documented in `docs/routed-dnssec-policy.md`, `docs/private-stub-dnssec.md`, and `docs/validating-forwarding.md`.

## Standards boundary

The delegating-stub path follows normal non-recursive referral semantics. The validating-forwarding path follows the validating-stub DNSSEC model: CD requests unsuppressed DNSSEC material from the recursive forwarder, AD is not relied upon, DS authenticates child DNSKEY state, and terminal data is accepted as secure only after local validation.

## Production boundary

`RoutingResolver`, `ForwardingResolver`, `ValidatingForwardingResolver`, `StubResolver`, `DelegatingStubResolver`, `ValidatingDelegatingStubResolver`, `PrivateTrustAnchorResolver`, and runtime self-target validation remain inside the isolated `internal/gcdns` development path. No production AdGuard Home, Unbound, NetBird/GoreeCloud Network nameserver assignment, client DNS setting, forwarding target, stub target, private trust anchor, Caddy rule, firewall rule, DHCP behavior, or production cutover is changed by this source milestone.
