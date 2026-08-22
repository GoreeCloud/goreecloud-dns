# Beacon Iterative DNSSEC Validation

GoreeCloud DNS has a staged validating iterative resolver in `internal/gcdns/iterative_dnssec.go`.

## Current trust flow

The validating path performs these steps before a secure positive answer may be returned:

1. Query the root zone for DNSKEY material with DNSSEC signaling enabled.
2. Authenticate the root DNSKEY RRset against the carried GoreeCloud Beacon root DS trust anchors.
3. Resolve the original question against the currently trusted authority set.
4. For every signed referral, authenticate the child DS RRset with the currently trusted parent DNSKEY set.
5. Query the child authority for its DNSKEY RRset.
6. Authenticate that DNSKEY RRset against the authenticated child DS RRset.
7. Carry only the resulting authenticated child DNSKEY set into the next secure delegation step.
8. When DS is absent, accept an insecure child only if a parent-signed exact-owner NSEC RRset proves that NS is present and DS is absent at the delegation point.
9. Once an insecure delegation is authenticated, preserve `DNSSECInsecure` below that boundary instead of attempting to recreate trust without another configured trust anchor.
10. For a positive terminal response, group the answer into RRsets and validate each RRset against matching RRSIG material using the authenticated DNSKEY set for the answering zone.
11. For an empty NOERROR response, allow exact-owner signed NSEC NODATA proof when the NSEC bitmap omits both the requested type and CNAME.
12. For an empty NXDOMAIN response, allow a conservative signed-NSEC proof only when Beacon authenticates an exact closest encloser, an NSEC interval covering the next-closer name, and an NSEC interval covering the wildcard below the closest encloser.

If a delegation cannot establish either secure DS trust or authenticated denial proving an intentionally unsigned child, the validating path stops before contacting the child authority. Positive terminal RRsets and malformed or cryptographically invalid denial proofs fail closed.

## NSEC authenticated-denial foundation

`internal/gcdns/dnssec_nsec.go` implements the current conservative authenticated-denial primitives.

Implemented source boundaries:

- signed exact-owner NSEC proof for intentionally unsigned delegations;
- rejection of delegation NSEC data that still advertises DS;
- requirement that an insecure delegation advertises NS and is not an SOA-bearing zone apex;
- signed exact-owner NSEC NODATA proof;
- DNSSEC canonical-name interval comparison including NSEC wrap-around intervals;
- explicit closest-encloser discovery from authenticated NSEC owner data;
- next-closer derivation and proof selection;
- wildcard nonexistence proof selection;
- empty-answer NXDOMAIN classification as secure only when closest-encloser, next-closer, and wildcard NSEC RRsets all validate with authenticated zone DNSKEYs;
- rejection of proof material that escapes the authenticated DNS zone;
- rejection of unsigned or cryptographically invalid NSEC proof;
- propagation of proven insecure state through the remaining recursive branch;
- no DNSKEY fetch for a child once its insecure delegation has been authenticated.

The NXDOMAIN implementation is intentionally stricter than the minimum proof layouts allowed by DNSSEC. Beacon currently requires an explicit exact-owner NSEC for the closest encloser rather than inferring existence from a more compact authority response. A valid but more compact proof therefore remains indeterminate instead of being over-trusted.

## Deliberate boundary

NSEC3 authenticated denial is not implemented yet. Delegations and negative answers that can only be proven through NSEC3 remain indeterminate and fail closed where secure classification is required.

NSEC wildcard-expanded positive-answer validation and less conservative NSEC NXDOMAIN proof layouts still require additional work. Positive CNAME/DNAME handling currently validates RRsets present in the terminal response, but complete signed alias-chain resolution across additional authority transitions remains a separate milestone.

## Production status

This code remains isolated from production DNS traffic. Existing production AdGuard Home and Unbound behavior is unchanged. Production cutover requires remaining DNSSEC work, broader resolver parity, executable testing, migration and rollback procedures, and GoreeCloud production-readiness acceptance.

## Next DNSSEC stages

- Implement NSEC3 authenticated denial for NXDOMAIN, NODATA, and insecure delegation proof.
- Extend NSEC wildcard handling to wildcard-expanded positive answers and supported compact denial layouts.
- Complete signed CNAME/DNAME chain validation across zone transitions.
- Add algorithm and digest policy with explicit unsupported-algorithm behavior.
- Add trust-anchor lifecycle and rollover automation.
- Add end-to-end runtime acceptance against controlled signed, unsigned, bogus, wildcard, NSEC, NSEC3, and denial-of-existence test zones.
