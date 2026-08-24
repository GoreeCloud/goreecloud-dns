# Beacon DNSSEC Cryptographic Policy

This document defines the current first-party cryptographic validation policy for the GoreeCloud Beacon DNSSEC implementation in `internal/gcdns`.

## Scope

The policy covers DNSSEC signing-algorithm validation support, DS delegation acceptance, DS digest validation, and DNSKEY strength checks. It is a resolver-validation policy, not an authoritative-zone signing policy and not a production-cutover authorization.

## Algorithm policy

Beacon explicitly accepts RSASHA1, RSASHA1-NSEC3-SHA1, RSASHA256, RSASHA512, ECDSAP256SHA256, ECDSAP384SHA384, and ED25519 for legacy/current RRSIG and DNSKEY validation where the implementation is available.

Beacon does not automatically accept every algorithm exposed by the underlying DNS library. Ed448 and other newer or MAY algorithms require a supported cryptographic implementation and deterministic acceptance tests before they can enter the accepted Beacon validation set.

## SHA-1 delegation transition

RSASHA1 and RSASHA1-NSEC3-SHA1 remain available for legacy RRSIG/DNSKEY validation, but Beacon does not permit those signing algorithms to establish a DS delegation. A delegation whose only otherwise usable DS records use those SHA-1 signing algorithms is classified `DNSSECInsecure`.

If the same delegation also contains an accepted modern DS algorithm, Beacon evaluates the modern DS normally. A mismatching modern DS remains `DNSSECBogus`; the presence of a SHA-1 DS cannot silently downgrade that failure to insecure.

## DS digest policy

Beacon validates DS digest types SHA-1, SHA-256, and SHA-384. SHA-1 remains available for validation compatibility even though new SHA-1 delegations are not accepted for creation under current DNSSEC guidance. Unsupported digest families remain explicit and cannot silently establish trust.

## DNSKEY strength policy

Beacon applies a key-strength check before a DNSKEY can authenticate a DS transition or verify an RRset.

For RSA DNSKEY algorithms, Beacon parses the RFC 3110/RFC 5702 exponent-and-modulus DNSKEY representation and accepts 1024-4096-bit RSA moduli for validation. RSA keys below 1024 bits are rejected as too weak. RSA keys above 4096 bits are outside the currently accepted Beacon validation envelope and are rejected rather than implicitly accepted.

ECDSAP256SHA256, ECDSAP384SHA384, and ED25519 have algorithm-defined key sizes. Beacon requires non-empty key material before passing those keys to the underlying cryptographic verifier; malformed material still fails cryptographic validation.

## Fail-closed integration

`DNSSECValidator.MatchDS` requires an accepted delegation algorithm, supported digest, matching DNSKEY, and acceptable DNSKEY strength before returning `DNSSECSecure`.

`DNSSECValidator.ValidateRRSet` requires a supported signature algorithm and an acceptable-strength matching DNSKEY before cryptographic signature verification. Unsupported-only signature material remains `DNSSECIndeterminate`; a supported signature that cannot validate with an acceptable trusted key fails closed as `DNSSECBogus`.

## Validation contract

`scripts/validate_dnssec_algorithm_policy.py` checks the source policy, validator integration, focused tests, this documentation, and CI wiring. The `beacon-native-core` job runs that source contract before `go test ./internal/gcdns`.

Focused tests cover algorithm acceptance, SHA-1 delegation handling, mixed-delegation downgrade resistance, unsupported algorithms, DS digest policy, accepted and rejected RSA modulus sizes, malformed RSA DNSKEY encoding, and fixed-size key-material requirements.

## Standards basis

RFC 9904 makes the IANA DNSSEC registries the canonical source of DNSSEC algorithm implementation and usage recommendations. RFC 9905 defines the SHA-1 DNSSEC transition behavior used by Beacon. RSA DNSKEY encoding and RSA/SHA-2 interoperability bounds follow the applicable DNSSEC RSA specifications, including RFC 3110 and RFC 5702.

## Remaining DNSSEC lifecycle work

The next cryptographic-lifecycle milestone is authenticated trust-anchor persistence and update handling, including explicit update approval, rollover state, recovery behavior, and reusable validation-state/cache lifecycle. This work remains isolated from production DNS until the broader GoreeCloud DNS acceptance gates are satisfied.
