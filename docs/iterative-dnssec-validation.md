# Beacon Iterative DNSSEC Validation

GoreeCloud DNS has a staged validating iterative resolver in `internal/gcdns/iterative_dnssec.go`.

## Current trust flow

The validating path performs these steps before a secure positive answer may be returned:

1. Query the root zone for DNSKEY material with DNSSEC signaling enabled.
2. Authenticate the root DNSKEY RRset against the carried GoreeCloud Beacon root DS trust anchors.
3. Resolve the original question against the currently trusted authority set.
4. For every referral, authenticate the child DS RRset with the currently trusted parent DNSKEY set.
5. Query the child authority for its DNSKEY RRset.
6. Authenticate that DNSKEY RRset against the authenticated child DS RRset.
7. Carry only the resulting authenticated child DNSKEY set into the next delegation step.
8. For a positive terminal response, group the answer into RRsets and validate each RRset against matching RRSIG material using the authenticated DNSKEY set for the answering zone.

If a delegation cannot establish secure trust, the validating path stops instead of querying the child authority. If a positive terminal RRset cannot establish secure DNSSEC validation, the answer fails closed instead of being labeled secure.

## Deliberate boundary

Negative and empty-answer responses are not yet classified secure or insecure. Absence of DS, NXDOMAIN, NODATA, wildcard denial, and related proofs require authenticated NSEC/NSEC3 processing before the resolver can distinguish a legitimate unsigned or nonexistent result from an unproven result.

Positive CNAME/DNAME handling currently validates RRsets present in the terminal response, but complete signed alias-chain resolution across additional authority transitions remains a separate milestone.

## Production status

This code remains isolated from production DNS traffic. Existing production AdGuard Home and Unbound behavior is unchanged. Production cutover requires remaining DNSSEC work, broader resolver parity, executable testing, migration and rollback procedures, and GoreeCloud production-readiness acceptance.

## Next DNSSEC stages

- Complete signed CNAME/DNAME chain validation across zone transitions.
- Implement NSEC authenticated denial.
- Implement NSEC3 authenticated denial.
- Validate wildcard proofs and closest-encloser logic.
- Add algorithm and digest policy with explicit unsupported-algorithm behavior.
- Add trust-anchor lifecycle and rollover automation.
- Add end-to-end runtime acceptance against controlled signed, unsigned, bogus, and denial-of-existence test zones.
