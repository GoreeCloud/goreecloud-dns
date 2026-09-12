# Beacon Resolver Authenticated Insecure Delegations

Beacon Resolver must never classify a child zone as DNSSEC-insecure merely because a referral omits DS records. A secure parent must cryptographically prove DS absence before the resolver crosses from a secure chain into an insecure subtree.

## Accepted proof forms

The current first-party implementation accepts conservative, signed proofs only:

- exact-name NSEC at the delegated child name, with NS present and DS absent from the type bitmap;
- exact-name NSEC3 matching the delegated child name, with NS present and DS absent from the type bitmap;
- every denial RRset used by the proof must validate against authenticated parent-zone DNSKEY material.

NSEC3 opt-out is not accepted yet and fails closed.

## Trust-state transition

After authenticated DS absence:

1. the delegated child is classified `DNSSECInsecure`;
2. Beacon Resolver does not fetch or require a child DNSKEY RRset;
3. terminal responses within that subtree are returned as insecure rather than secure or bogus solely because they are unsigned;
4. deeper referrals remain insecure even if they advertise DS records, because an unsigned parent cannot authenticate those DS records;
5. secure status can only be re-established through an independently configured trust anchor, which is not part of this milestone.

This prevents accidental trust resurrection beneath an authenticated insecure boundary.

## Fail-closed boundaries

The resolver rejects or leaves indeterminate any delegation whose DS absence cannot be authenticated. It also rejects NSEC/NSEC3 proof material that does not identify an actual delegation, advertises DS, lacks required signatures, uses inconsistent NSEC3 parameters, or depends on unsupported opt-out semantics.

## Production boundary

This source milestone remains isolated from the inherited production DNS request path. It does not constitute production acceptance or retirement of AdGuard Home or Unbound.
