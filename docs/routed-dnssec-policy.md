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

## Routing-runtime safety

A DNSSEC-validation wrapper must not hide its underlying forward or stub target from routing safety checks. `routing_runtime_validation.go` therefore unwraps `PrivateTrustAnchorResolver` when discovering configured native target endpoints.

When a private trust-anchor wrapper contains `DelegatingStubResolver`, `NewRuntimeValidatedRoutingResolver` recursively clones the wrapper and attaches the active listener boundary to the inner delegating stub. Dynamically discovered child-authority addresses remain subject to the same self-target rejection before exchange.

## Current delegation boundary

This private trust-anchor stage validates terminal data with the authenticated key set from the configured zone apex. It does not yet establish and carry a private DNSSEC trust chain through signed child delegations below that apex.

A terminal answer signed by a separate delegated child zone therefore does not become secure merely because the parent private zone is anchored. Private DS/DNSKEY delegation walking, authenticated insecure-delegation transitions below a private anchor, and per-child private trust-anchor policy remain staged work.

The same limitation applies when a `DelegatingStubResolver` follows private subdelegations: referral transport can reach the child, but local DNSSEC trust does not automatically cross the child delegation in this stage.

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
- runtime self-target validation through a private trust-anchor wrapper; and
- propagation of the runtime listener boundary through a wrapped delegating stub.

The focused routed-DNSSEC source contract is executed by the `beacon-native-core` workflow before `go test ./internal/gcdns`.

## Production boundary

This code remains isolated in `internal/gcdns`. No production AdGuard Home, Unbound, NetBird/GoreeCloud Network DNS assignment, DNS listener, forwarding target, stub target, private DNS zone, trust-anchor configuration, filtering, DHCP, Caddy, firewall, credential, or client cutover state is changed by this development milestone.
