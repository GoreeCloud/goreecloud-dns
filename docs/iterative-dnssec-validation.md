# Beacon Iterative DNSSEC Validation

GoreeCloud DNS has a staged validating iterative resolver in `internal/gcdns/iterative_dnssec.go`.

## Current trust flow

The validating path performs these steps before a secure answer may be returned:

1. Query the root zone for DNSKEY material with DNSSEC signaling enabled.
2. Authenticate the root DNSKEY RRset against the carried GoreeCloud Beacon root DS trust anchors.
3. Resolve the original question against the currently trusted authority set.
4. For every signed referral, authenticate the child DS RRset with the currently trusted parent DNSKEY set.
5. Query the child authority for its DNSKEY RRset.
6. Authenticate that DNSKEY RRset against the authenticated child DS RRset.
7. Carry only the resulting authenticated child DNSKEY set into the next secure delegation step.
8. When DS is absent, accept an insecure child only when signed NSEC or exact-name NSEC3 proof establishes an actual delegation with NS present and DS absent.
9. Once an insecure delegation is authenticated, preserve `DNSSECInsecure` below that boundary instead of attempting to recreate trust without another configured trust anchor.
10. For a positive terminal response, group the answer into RRsets and validate each RRset against matching RRSIG material using the authenticated DNSKEY set for the answering zone.
11. If a validated positive RRSIG has fewer `RRSIG Labels` than its expanded owner name, treat the RRset as wildcard synthesized and require authenticated proof that the wildcard was the correct match.
12. For an empty NOERROR response, authenticate exact-owner NODATA first and then allow wildcard NODATA only when the wildcard owner lacks the requested type and no closer match exists.
13. For an empty NXDOMAIN response, allow conservative signed NSEC or NSEC3 proof only when Beacon authenticates closest-encloser, next-closer, and wildcard nonexistence evidence.

If a delegation cannot establish either secure DS trust or authenticated denial proving an intentionally unsigned child, the validating path stops before contacting the child authority. Positive terminal RRsets and malformed or cryptographically invalid denial proofs fail closed.

## NSEC authenticated denial

`internal/gcdns/dnssec_nsec.go` implements the unhashed authenticated-denial primitives.

Implemented source boundaries include signed exact-owner proof for intentionally unsigned delegations, exact-owner NODATA proof, canonical NSEC interval processing including wrap-around, conservative NXDOMAIN closest-encloser/next-closer/wildcard proof, authenticated-zone boundary checks, and fail-closed handling for unsigned or invalid proof material.

The NXDOMAIN implementation remains intentionally stricter than the minimum proof layouts allowed by DNSSEC. Beacon currently requires explicit closest-encloser NSEC evidence rather than inferring existence from every valid compact proof layout.

## NSEC3 authenticated denial

`internal/gcdns/dnssec_nsec3.go` implements the hashed denial path.

Beacon currently supports exact-name NSEC3 NODATA, closest-encloser/next-closer/wildcard NSEC3 NXDOMAIN proof, and exact-name NSEC3 proof for intentionally unsigned delegations. Proof records must use a consistent supported SHA-1 parameter set, remain inside the authenticated zone, and validate cryptographically with authenticated DNSKEY material.

NSEC3 opt-out delegation semantics remain deliberately fail closed. Unsupported opt-out proof is not used to infer insecurity.

## Wildcard-expanded positive answers

`internal/gcdns/dnssec_wildcard.go` closes the positive-answer wildcard validation gap identified by RFC 4035 and RFC 5155.

A positive RRset is first cryptographically verified. If a valid signature has a `RRSIG Labels` value equal to the RRset owner-label count, Beacon accepts it as an ordinary directly signed RRset without a wildcard denial proof. A literal wildcard owner such as `*.example.test.` remains an exact-owner response even though DNSSEC excludes the leading wildcard label from its RRSIG Labels count. If a validated signature on a non-wildcard owner has fewer labels, Beacon derives the immediate ancestor of the generating wildcard and the corresponding next-closer name.

For NSEC responses, Beacon requires a signed NSEC interval covering the next-closer name. An authenticated exact-owner NSEC at that name instead proves that a closer name exists and makes the wildcard expansion bogus.

For NSEC3 responses, Beacon requires a signed NSEC3 RR covering the next-closer hash. A matching authenticated NSEC3 RR instead proves that the closer name exists and makes the expansion bogus. The current NSEC3 wildcard path inherits the conservative no-opt-out policy used by the existing NSEC3 denial validator.

A cryptographically valid wildcard-expanded answer without the required no-closer-match proof fails closed and is not classified `DNSSECSecure`.

## Wildcard NODATA

Empty NOERROR responses can also result from a wildcard matching QNAME while the wildcard owner lacks QTYPE. Beacon now validates these responses explicitly instead of treating them as ordinary exact-owner NODATA.

For NSEC, Beacon selects the closest wildcard-owner NSEC applicable to QNAME, authenticates its RRset, requires its bitmap to omit both QTYPE and CNAME, derives the next-closer name from the wildcard's immediate ancestor, and then requires the same signed no-closer-match NSEC proof used by wildcard-positive validation.

For NSEC3, Beacon requires an authenticated closest-encloser proof, authenticated NSEC3 coverage of the next-closer name, and an authenticated NSEC3 RR matching the corresponding wildcard owner. The wildcard NSEC3 bitmap must omit both QTYPE and CNAME. The current implementation continues to reject opt-out proof sets rather than applying opt-out semantics outside a separately reviewed boundary.

## Deliberate boundary

Safe NSEC3 opt-out handling, broader compact NSEC proof layouts, full signed CNAME/DNAME chain resolution across additional authority transitions, DNSSEC algorithm/key-size policy, and authenticated trust-anchor persistence/rollover remain staged work.

## Production status

This code remains isolated from production DNS traffic. Existing production AdGuard Home and Unbound behavior is unchanged. Production cutover requires remaining DNSSEC work, broader resolver parity, executable testing, migration and rollback procedures, and GoreeCloud production-readiness acceptance.

## Next DNSSEC stages

- Add safe NSEC3 opt-out handling only for proof forms where opt-out semantics are valid.
- Broaden supported compact NSEC denial layouts without weakening fail-closed proof requirements.
- Complete signed CNAME/DNAME chain validation across zone transitions.
- Add algorithm and digest policy with explicit unsupported-algorithm behavior.
- Add trust-anchor lifecycle and rollover automation.
- Add end-to-end runtime acceptance against controlled signed, unsigned, bogus, wildcard, NSEC, NSEC3, and denial-of-existence test zones.
