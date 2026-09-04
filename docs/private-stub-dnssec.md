# Private Stub DNSSEC Trust Carry

GoreeCloud Beacon can carry locally authenticated DNSSEC trust through delegated children of an explicitly anchored private stub namespace without trusting an upstream AD bit.

## Construction

`NewValidatingDelegatingStubResolver` combines four existing first-party boundaries:

- the bounded private namespace and referral rules of `DelegatingStubResolver`;
- an out-of-band `PrivateDNSKEYTrustAnchor` for the exact stub-zone apex;
- `DNSSECValidator` DS, DNSKEY, denial, and terminal-answer primitives; and
- the runtime listener self-target boundary supplied by `NewRuntimeValidatedRoutingResolver`.

The configured stub zone must be explicit and nonblank. The configured trust-anchor zone must exactly match the stub zone. The trust anchor itself must satisfy the same zone-DNSKEY requirements enforced by `PrivateTrustAnchorResolver`.

## Apex trust

Before processing the requested name, Beacon queries the configured stub authorities for the stub-zone apex DNSKEY RRset with RD=0, DO enabled, and CD=1. The configured DNSKEY trust anchor must appear in and authenticate the complete apex DNSKEY RRset before that returned keyset becomes trusted.

Upstream AD is cleared and ignored. The configured anchor is out-of-band trust configuration, not data learned from the DNS response.

## Secure child delegation

When an anchored private parent returns a referral to a signed child, Beacon:

1. requires the referral to remain strictly below the configured stub namespace and to be closer to the requested name;
2. authenticates the child DS RRset using the currently authenticated parent DNSKEY set;
3. resolves the child authoritative endpoints through the existing conservative referral planner;
4. applies the active runtime listener/self-target boundary to every resulting child endpoint before exchange;
5. queries the child authority for its apex DNSKEY RRset with RD=0, DO enabled, and CD=1;
6. matches child DNSKEY material to the authenticated parent DS records;
7. requires a DS-authenticated child key to authenticate the complete child apex DNSKEY RRset; and
8. carries only that authenticated child DNSKEY set into the next delegation or terminal-answer validation step.

This is the same DNSSEC trust-chain relationship used by Beacon's validating Internet recursion, but it begins from the configured private-zone DNSKEY anchor rather than the root trust-anchor set.

## Authenticated insecure child

A private child is not treated as unsigned merely because its referral omits DS. The parent must authenticate DS absence through the existing NSEC, exact-name NSEC3, or scoped NSEC3 Opt-Out insecure-delegation proof.

After that proof establishes `DNSSECInsecure`, Beacon does not query or require the child's DNSKEY RRset. The insecure state persists through deeper referrals and is not silently upgraded by a deeper DS record. Re-establishing trust requires another explicit trust anchor.

A referral with neither authenticated DS nor authenticated DS-absence proof fails before Beacon contacts the child authority.

## Terminal data

On a secure branch, terminal positive and negative answers must pass `DNSSECValidator.AuthenticateTerminalAnswer` using the authenticated DNSKEY set for the current zone. Secure wildcard, CNAME/DNAME, NSEC, NSEC3, Opt-Out boundary, NXNAME, and Compact Denial rules therefore remain the same as the validating iterative resolver.

On an authenticated insecure branch, terminal authoritative data is returned as `DNSSECInsecure` and is not rejected merely for lacking DNSSEC signatures.

Upstream AD is always cleared. CD is forced only for upstream validation work and the original downstream CD value is restored on the terminal response.

## Stub namespace and referral restrictions

Private DNSSEC trust does not weaken the existing stub-routing boundaries:

- every referral remains inside the configured stub namespace;
- every referral must move strictly closer to the QNAME;
- no more than 16 stub delegation transitions are permitted;
- mandatory in-domain glue remains fail-closed;
- sibling Additional-section addresses are not trusted as glue;
- sibling NS hostnames may be resolved only through the same configured stub namespace;
- nameserver hostnames outside the stub namespace are not sent into public recursion; and
- dynamically discovered child targets are rejected if they point back into an active GoreeCloud DNS listener.

## Address discovery

Same-namespace sibling nameserver A/AAAA discovery uses the validating private stub resolver itself and shares the request-scoped nameserver-discovery state. The address lookup therefore begins again from the configured apex trust anchor and independently establishes the applicable secure or insecure path for that nameserver name.

A discovered IP address identifies where to send DNS transport. It does not by itself authenticate the referred child.

## Alias routing boundary

The validating private stub resolver authenticates a terminal CNAME or DNAME RRset using the current private trust chain. Higher-level `RoutingResolver` alias processing remains responsible for reselecting the route for an unresolved alias target. An alias that leaves the private namespace therefore does not inherit the private trust anchor automatically.

## Tests

Deterministic source tests cover:

- private apex trust-anchor authentication;
- secure parent DS to child DNSKEY trust carry;
- terminal data signed by an authenticated child ZSK;
- authenticated NSEC DS-absence transition into an insecure child;
- absence of child DNSKEY acquisition after an insecure transition;
- rejection of an unproven child delegation before child contact;
- exact trust-anchor/stub-zone matching;
- out-of-zone request rejection;
- blank stub-zone rejection;
- configured validating-stub self-target rejection;
- runtime listener-boundary attachment; and
- rejection of a dynamically discovered child authority that points back into an active GoreeCloud DNS listener.

## Internet-forwarding boundary

Raw `ForwardingResolver` remains `DNSSECIndeterminate` and never becomes trusted because an upstream recursive resolver sets AD. `ValidatingForwardingResolver` is the separate Internet-forwarding path that establishes the normal root-to-signer DNSSEC chain locally with RD=1, DO, and CD while ignoring upstream AD.

Private stub trust anchors remain namespace-specific and are not reused to authenticate arbitrary Internet forwarding. The validating forwarder begins from Beacon's root DS trust anchors instead.

Trust-anchor provisioning, persistence, authorized updates, rollover, backup/recovery, DNSSEC algorithm and key-size policy, target-environment runtime execution, and production acceptance remain separate stages.

## Production boundary

`ValidatingDelegatingStubResolver` remains isolated in `internal/gcdns`. No production private zone, trust anchor, forward/stub route, DNS listener, AdGuard Home, Unbound, GoreeCloud Network/NetBird assignment, filtering, DHCP, Caddy, firewall, authoritative DNS, encrypted DNS, credentials, or client DNS state is changed by this source milestone.
