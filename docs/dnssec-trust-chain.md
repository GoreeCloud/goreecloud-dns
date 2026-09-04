# Beacon DNSSEC Trust-Chain Boundary

Beacon DNSSEC validation treats trust as an explicit chain rather than as a property of whatever DNSKEY records arrive in a response.

## Parent DS to child DNSKEY

A parent-zone DS RRset must already be authenticated before it can establish trust in a child zone. `DNSSECValidator.TrustedKeysForDS` returns only child DNSKEYs whose owner, algorithm, key tag, and supported DS digest match that authenticated DS RRset.

Beacon does not trust unrelated DNSKEYs simply because they are present in the same response.

## DNSKEY RRset authentication

`DNSSECValidator.AuthenticateDNSKEYResponse` requires two conditions before a child DNSKEY set is promoted to secure trust state:

1. At least one DNSKEY must match the authenticated parent DS RRset.
2. The complete DNSKEY RRset must carry an RRSIG that validates using a DS-authenticated DNSKEY.

A DS-matching key without a valid DNSKEY RRset signature is therefore rejected as bogus.

## Delegation DS authentication

`DNSSECValidator.AuthenticateDelegationDS` validates a child DS RRset with authenticated parent-zone DNSKEYs before the DS records can be used to establish child trust.

A DS RRset without a valid RRSIG is rejected as bogus. Absence of DS remains indeterminate until Beacon implements authenticated denial through NSEC or NSEC3; simple absence is never treated as proof that a child is legitimately unsigned.

## Current boundary

These helpers establish the cryptographic trust-transition contract but are not yet wired through every hop of `IterativeResolver`. Root DNSKEY acquisition, parent-key state carry, child DNSKEY queries, authenticated denial, wildcard proofs, and terminal-answer trust evaluation remain required before Beacon DNSSEC is production-complete.

The native path remains isolated from production DNS. AdGuard Home and Unbound continue to provide the existing runtime path until the GoreeCloud DNS replacement passes explicit acceptance.
