# Beacon Iterative DNSSEC Validation

GoreeCloud DNS now has a staged validating iterative resolver in `internal/gcdns/iterative_dnssec.go`.

## Current trust flow

The validating path performs these steps before a delegation is trusted:

1. Query the root zone for DNSKEY material with DNSSEC signaling enabled.
2. Authenticate the root DNSKEY RRset against the carried GoreeCloud Beacon root DS trust anchors.
3. Resolve the original question against the currently trusted authority set.
4. For every referral, authenticate the child DS RRset with the currently trusted parent DNSKEY set.
5. Query the child authority for its DNSKEY RRset.
6. Authenticate that DNSKEY RRset against the authenticated child DS RRset.
7. Carry only the resulting authenticated child DNSKEY set into the next delegation step.

If a delegation cannot establish secure trust, the validating path stops instead of querying the child authority.

## Deliberate boundary

The validating iterative resolver does **not** yet classify terminal answers as `secure`. A secure delegation chain proves the authority relationship, but the final answer RRset still requires its own RRSIG validation. Terminal results therefore remain `indeterminate` until answer-RRset validation is integrated.

Unsigned delegations also remain unsupported in this path because absence of DS cannot safely establish an insecure delegation until NSEC/NSEC3 authenticated denial is implemented. An unproven delegation therefore fails closed.

## Production status

This code remains isolated from production DNS traffic. Existing production AdGuard Home and Unbound behavior is unchanged. Production cutover requires the remaining DNSSEC work, broader resolver parity, executable testing, migration and rollback procedures, and GoreeCloud production-readiness acceptance.

## Next DNSSEC stages

- Validate terminal positive-answer RRsets and CNAME/DNAME chains.
- Implement NSEC authenticated denial.
- Implement NSEC3 authenticated denial.
- Validate wildcard proofs and closest-encloser logic.
- Add algorithm and digest policy with explicit unsupported-algorithm behavior.
- Add trust-anchor lifecycle and rollover automation.
- Add end-to-end runtime acceptance against controlled signed, unsigned, bogus, and denial-of-existence test zones.
