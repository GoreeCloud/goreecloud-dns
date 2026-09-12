# Beacon Locally Validating Forwarding

GoreeCloud Beacon can use a recursive forwarding server as a DNS transport without delegating DNSSEC trust to that server.

`ForwardingResolver` remains the raw forwarding transport. It sets RD, requests DNSSEC material, clears received AD, and returns `DNSSECIndeterminate`. `ValidatingForwardingResolver` is a separate wrapper that establishes DNSSEC state locally.

## Trust model

The production constructor uses the built-in Beacon root DS trust-anchor set. The explicit-root constructor is internal and exists so deterministic tests can build a synthetic root hierarchy without requiring real root private-key material.

For locally validated forwarding, Beacon sends the terminal query and its DNSSEC support queries through the configured recursive forward targets with:

- RD set, because the selected targets are recursive forwarders;
- DO set, so DNSSEC records are returned;
- CD set, so the upstream does not suppress data according to its own DNSSEC validation policy; and
- upstream AD ignored and cleared before local trust decisions.

This follows the validating-stub model: the forwarding server supplies DNS data, while Beacon performs the authentication decision.

## Secure trust walk

When a forwarded response contains DNSSEC signatures, Beacon identifies the single RRSIG signer zone for the response fragment being validated and establishes trust only to that signer zone. This avoids unnecessary DS probes at ordinary owner names, CNAME owners, and Empty Non-Terminal names.

Starting from the authenticated root DNSKEY RRset, Beacon evaluates candidate names from the root outward toward the signer zone:

1. query DS for the candidate through the forwarder with CD and DO;
2. authenticate a positive DS RRset using the current parent DNSKEY set;
3. when the DS is secure, query the candidate DNSKEY RRset and authenticate it against that DS before carrying the child keyset forward;
4. when signed NSEC, exact-name NSEC3, or the already supported scoped NSEC3 Opt-Out delegation proof authenticates DS absence at a delegation, transition to `DNSSECInsecure` and do not restore trust below that boundary without another explicit trust anchor;
5. when the candidate is not a delegation, require authenticated exact-name DS NODATA whose bitmap does not identify a delegation before continuing with the same parent keyset; and
6. fail closed when DS state cannot be classified securely.

The label walk is bounded by `maxForwardValidationLabels` and therefore cannot grow without limit on attacker-controlled names.

## Parent-side DS queries

DS is parent-side data. If the downstream client itself asks for DS at QNAME, Beacon stops the trust walk at the parent and validates the returned DS RRset with the authenticated parent DNSKEY set. It does not cross into the child and then attempt to validate the parent-side DS RRset with child keys.

## Authenticated insecure forwarding

A forwarded response may be accepted as `DNSSECInsecure` only after the secure chain has authenticated a delegation transition with no DS. A missing DS record by itself is insufficient.

After an authenticated insecure transition, Beacon does not require signatures on terminal data below that boundary and does not treat a deeper DS as a way to restore secure trust. This matches the existing iterative and private-stub weakest-link trust model.

## Alias handling

Recursive forwarders may return a complete CNAME or DNAME chain containing data from more than one zone in one response. Beacon does not validate target-zone data using the source alias zone's keys.

For an alias at the current owner, Beacon isolates the locally applicable CNAME or DNAME link and its DNSSEC material, authenticates that link against the source signer zone, then issues a fresh locally validated forwarding query for the alias target. The completed chain is merged under the original question only after every hop reaches a determinate trust state.

Alias processing retains the existing 16-transition bound and loop detection. A secure hop followed by an authenticated insecure hop produces an insecure completed chain; bogus or indeterminate secure-branch data fails closed.

## Non-delegation proof boundary

The forwarding trust walk needs to distinguish a real delegated child from an ordinary label that merely lies between the current authenticated zone and a deeper signed delegation.

`AuthenticateNonDelegationDS` currently accepts conservative exact-name NSEC or exact-name non-Opt-Out NSEC3 DS-NODATA proof after cryptographic validation with the current parent keys. A bitmap that identifies delegation NS is not treated as a non-delegation.

More compact Empty Non-Terminal proof layouts, generalized NSEC3 Opt-Out non-delegation inference, and other proof forms are not inferred optimistically in this stage. If the recursive forwarder does not return proof that fits the supported authenticated form, the trust walk fails rather than silently skipping the name.

## Multiple signer zones

One response fragment being validated must resolve to one DNSSEC signer zone. Alias handling deliberately splits a multi-zone chain into separately validated hops. A non-alias response fragment that still contains multiple distinct signer zones fails closed rather than choosing one keyset heuristically.

## Runtime routing safety

`routing_runtime_validation.go` exposes the underlying targets of `ValidatingForwardingResolver`. A validating-forward route therefore cannot hide a configured target that points back to an active GoreeCloud DNS listener.

This first stage has no dynamic referral targets because the forwarding server remains the only network target. Listener self-target validation therefore applies to the configured forwarder endpoints.

## Current lifecycle boundary

The validating forwarder re-establishes the needed trust chain for each resolution. Persistent authenticated DNSKEY/DS validation caches, aggressive trust-chain reuse, trust-anchor lifecycle automation, RFC 8020 cuts, broader non-delegation denial layouts, encrypted forwarding transports, and target-environment performance acceptance remain later work.

Raw `ForwardingResolver` remains available as explicitly non-validating transport and continues to return `DNSSECIndeterminate`. Local validation occurs only when the route is configured with `ValidatingForwardingResolver`.

## Production boundary

This implementation remains isolated inside `internal/gcdns`. No production AdGuard Home, Unbound, GoreeCloud Network/NetBird nameserver assignment, forwarding target, DNS listener, filtering, DHCP, Caddy, firewall, authoritative DNS, encrypted DNS endpoint, credential, client resolver configuration, or cutover state is changed by this source milestone.
