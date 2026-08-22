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

If a delegation cannot establish either secure DS trust or authenticated denial proving an intentionally unsigned child, the validating path stops before contacting the child authority. Positive terminal RRsets also fail closed when their signatures do not validate.

## NSEC authenticated-denial foundation

`internal/gcdns/dnssec_nsec.go` introduces the first conservative authenticated-denial primitives.

Implemented source boundaries:

- signed exact-owner NSEC proof for intentionally unsigned delegations;
- rejection of delegation NSEC data that still advertises DS;
- requirement that an insecure delegation advertises NS and is not an SOA-bearing zone apex;
- signed exact-owner NSEC NODATA proof;
- rejection of unsigned or cryptographically invalid NSEC proof;
- propagation of proven insecure state through the remaining recursive branch;
- no DNSKEY fetch for a child once its insecure delegation has been authenticated.

## Deliberate boundary

NXDOMAIN is still `indeterminate`. A correct authenticated NXDOMAIN result requires closest-encloser and wildcard nonexistence proof, not merely one NSEC interval covering the queried name. Beacon will not take that shortcut.

NSEC3 authenticated denial is also not implemented yet. Therefore delegations and negative answers that can only be proven through NSEC3 remain indeterminate and fail closed where secure classification is required.

Positive CNAME/DNAME handling currently validates RRsets present in the terminal response, but complete signed alias-chain resolution across additional authority transitions remains a separate milestone.

## Production status

This code remains isolated from production DNS traffic. Existing production AdGuard Home and Unbound behavior is unchanged. Production cutover requires remaining DNSSEC work, broader resolver parity, executable testing, migration and rollback procedures, and GoreeCloud production-readiness acceptance.

## Next DNSSEC stages

- Implement complete NSEC NXDOMAIN closest-encloser and wildcard denial validation.
- Implement NSEC3 authenticated denial for NXDOMAIN, NODATA, and insecure delegation proof.
- Complete signed CNAME/DNAME chain validation across zone transitions.
- Add algorithm and digest policy with explicit unsupported-algorithm behavior.
- Add trust-anchor lifecycle and rollover automation.
- Add end-to-end runtime acceptance against controlled signed, unsigned, bogus, and denial-of-existence test zones.
