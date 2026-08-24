# Routed DNSSEC Policy

GoreeCloud Beacon keeps resolver routing and DNSSEC trust as separate decisions. A route may select direct recursion, forwarding, a terminal-only stub, or a delegating stub, but the selected transport does not become DNSSEC trust evidence by itself.

## Default routed-data state

`ForwardingResolver`, `StubResolver`, and `DelegatingStubResolver` clear any received `AD` bit and return `DNSSECIndeterminate`. Beacon does not accept an upstream recursive resolver's AD assertion or an authoritative server response as equivalent to local DNSSEC validation.

Direct Internet recursion may continue through `ValidatingIterativeResolver`, which establishes trust from the configured root trust-anchor set and validates the delegation chain and terminal response locally.

## Explicit private DNSKEY trust anchors

`internal/gcdns/routed_dnssec_policy.go` adds `PrivateTrustAnchorResolver` for a private or otherwise locally administered signed namespace whose DNSKEY trust anchor is configured through an authenticated out-of-band mechanism.

The configured zone must be explicit and nonblank. Every configured anchor must be a valid zone DNSKEY for that exact zone. The constructor defensively copies the anchor material and rejects empty or malformed key sets.

For each routed query under the configured namespace, Beacon:

1. issues an apex `DNSKEY` lookup through the wrapped routed resolver;
2. forces `CD=1` on that upstream lookup so the wrapped resolver returns DNSSEC material without substituting its own validation policy for Beacon's local decision;
3. ignores any upstream `AD` assertion;
4. requires a configured DNSKEY trust anchor to appear in the returned apex DNSKEY RRset;
5. requires that configured anchor to authenticate an RRSIG over the complete apex DNSKEY RRset;
6. treats the complete authenticated apex DNSKEY RRset as the locally trusted key set;
7. performs the routed terminal query with `CD=1`, again ignoring upstream AD;
8. validates the terminal answer through the existing `DNSSECValidator.AuthenticateTerminalAnswer` path; and
9. returns `DNSSECSecure` only after local validation succeeds.

The internally forced CD bit is not leaked downstream. Before a validated result is returned, Beacon restores the original client's CD value and keeps AD cleared because AD from the wrapped transport was never accepted as evidence.

## Trust-anchor semantics

`internal/gcdns/dnssec_trust_anchor.go` implements the configured-DNSKEY trust-anchor primitive. A returned apex key set is not trusted merely because one returned key resembles a configured key. The configured DNSKEY must be present in the apex DNSKEY RRset and must validate a signature over that complete DNSKEY RRset before additional apex keys, including ordinary zone-signing keys, become trusted.

This lets a configured KSK authenticate the apex DNSKEY RRset and then allows a ZSK from that authenticated keyset to validate ordinary terminal RRsets.

Trust-anchor material is configuration, not data learned from the routed DNS response. Provisioning, secure storage, update approval, rollover, backup, recovery, and audit of private trust anchors remain separate lifecycle responsibilities.

## Private child-delegation trust carry

`ValidatingDelegatingStubResolver` extends the private anchor model through delegated children inside the configured stub namespace.

The validating stub first authenticates the configured private apex DNSKEY RRset from the out-of-band anchor. At each closer referral, Beacon then applies the same DS/DNSKEY transition already used by validating Internet recursion:

- an authenticated child DS RRset is validated with the current parent DNSKEY set;
- child authoritative addresses are obtained through the bounded private-stub referral planner;
- the child apex DNSKEY RRset is queried with RD=0, DO enabled, and CD=1;
- a DNSKEY matching the authenticated DS must authenticate the complete child apex DNSKEY RRset; and
- only the resulting authenticated child keyset is carried into the next delegation or terminal-answer check.

A missing DS is not enough to classify a child as unsigned. Existing NSEC, exact-name NSEC3, and scoped NSEC3 Opt-Out insecure-delegation validation must authenticate DS absence. After that transition, the branch becomes `DNSSECInsecure`, child DNSKEY acquisition is skipped, and deeper referrals cannot restore secure trust without a separate explicit anchor.

A referral that provides neither authenticated DS nor authenticated DS-absence proof fails before the child authority is contacted.

Secure terminal data is validated through `AuthenticateTerminalAnswer` using the current authenticated child keyset. Authenticated-insecure terminal data is returned as `DNSSECInsecure` without requiring signatures that the proven unsigned child cannot provide.

The validating private stub keeps every existing namespace and operational bound: referrals must remain below the configured stub apex, must move strictly closer to QNAME, are limited to 16 transitions, keep mandatory in-domain glue fail-closed, refuse public recursion for nameservers outside the private stub namespace, and apply runtime listener self-target checks to dynamically discovered child endpoints.

The detailed implementation boundary is in `docs/private-stub-dnssec.md`.

## Routing-runtime safety

A DNSSEC-validation wrapper must not hide its underlying forward or stub target from routing safety checks. `routing_runtime_validation.go` therefore unwraps `PrivateTrustAnchorResolver` when discovering configured native target endpoints.

`NewRuntimeValidatedRoutingResolver` also recognizes `ValidatingDelegatingStubResolver`, validates its configured root-authority endpoints, clones it with the active runtime boundary attached, and applies that boundary to every dynamically discovered child-authority endpoint before exchange.

When a private trust-anchor wrapper contains `DelegatingStubResolver`, runtime construction still recursively clones the wrapper and attaches the active listener boundary to the inner delegating stub. DNSSEC validation layers therefore do not create a self-target bypass.

## Internet forwarding boundary

A private DNSKEY anchor is not a substitute for validating arbitrary Internet forwarding. Ordinary forwarded Internet data remains `DNSSECIndeterminate` until Beacon implements a local forwarding-validation path that builds the normal root-to-zone DNSSEC chain or routes the query through the validating iterative resolver.

No policy in this stage permits promoting a forwarded result because an upstream server set AD.

## Tests and source contract

Deterministic source tests cover:

- configured KSK authentication of an apex DNSKEY RRset;
- use of an authenticated ZSK for terminal data;
- forced upstream CD behavior;
- restoration of the downstream CD bit;
- preservation of client identity and client address context;
- rejection of unsigned terminal data even when upstream AD is set;
- rejection when the configured anchor is absent from the apex DNSKEY RRset;
- rejection when the configured anchor does not authenticate the DNSKEY RRset;
- rejection of malformed, non-zone-key, empty, or blank-zone trust-anchor configuration;
- rejection of questions outside the anchored namespace;
- secure private parent-DS to child-DNSKEY trust carry;
- authenticated insecure private child transition without child DNSKEY lookup;
- rejection of unproven private child delegations before child contact;
- exact validating-stub/trust-anchor namespace matching;
- runtime root self-target validation for validating private stubs;
- runtime listener-boundary attachment to validating private stubs; and
- dynamic child-authority self-target rejection before child contact.

The focused routed-DNSSEC and private-stub DNSSEC source contracts are executed by the `beacon-native-core` workflow before `go test ./internal/gcdns`.

## Production boundary

This code remains isolated in `internal/gcdns`. No production AdGuard Home, Unbound, NetBird/GoreeCloud Network DNS assignment, DNS listener, forwarding target, stub target, private DNS zone, trust-anchor configuration, filtering, DHCP, Caddy, firewall, credential, or client cutover state is changed by this development milestone.
