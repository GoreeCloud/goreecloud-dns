# Beacon QNAME Minimisation

GoreeCloud Beacon implements the first native RFC 9156 QNAME minimisation stage in `internal/gcdns/qname_minimisation.go`, `internal/gcdns/iterative.go`, and `internal/gcdns/iterative_dnssec.go`.

## Resolver behavior

For ordinary Internet data queries, Beacon uses a fixed A minimisation QTYPE that is independent of the incoming QTYPE. Starting from the current known authority boundary, each minimisation probe exposes only one additional label from the original QNAME. Referrals advance the known authority boundary; non-referral NOERROR responses, including NODATA and CNAME responses, advance the minimisation cursor without being returned as the client's final answer.

The original full QNAME and original QTYPE are sent only after the resolver has built the QNAME to the final name or when compatibility fallback disables minimisation for the current resolution path.

Parent-side and meta/transfer query types such as DS remain on the traditional iterative path in this first implementation. Their special RFC 9156 handling is staged rather than approximated.

## Query amplification bound

RFC 9156 requires resolvers that implement QNAME minimisation to limit the number of outgoing queries attributable to minimisation. Beacon shares a request-scoped budget through `resolutionState` and permits at most 10 minimisation probes for one top-level resolution, including alias and authoritative-NS-address work that shares that resolution state.

When the 10-probe budget is exhausted, Beacon stops issuing minimisation probes and continues with the normal full-QNAME iterative path. This preserves correctness while bounding query amplification. The first implementation adds one label per probe rather than applying the optional multi-label distribution optimization described by RFC 9156.

## Compatibility fallback

Beacon uses a relaxed compatibility boundary. If a minimised exchange fails, returns a response code outside NOERROR/NXDOMAIN, or returns DNAME where existing alias handling should own the result, Beacon stops minimising that resolution path and retries using the original full question.

Beacon does not yet use RFC 8020 NXDOMAIN cuts during QNAME minimisation. An ancestor NXDOMAIN response therefore does not terminate the original request merely because it was received during minimisation; Beacon continues building the QNAME or falls back to the ordinary full-query path as appropriate.

## DNSSEC

The validating iterative resolver uses the same fixed A probes and request-scoped limit, but secure minimisation responses are allowed to influence zone-cut discovery only after DNSSEC authentication with the currently authenticated zone DNSKEYs.

A secure referral continues through the existing DS/DNSKEY delegation-authentication path. A secure non-referral minimisation response must authenticate as `DNSSECSecure` before Beacon advances the minimisation cursor. If the response is indeterminate and the branch is otherwise secure, Beacon abandons minimisation for that path and sends the full original query instead of using unproven data to infer zone-cut state. Cryptographically bogus minimisation material fails through the existing DNSSEC authentication boundary.

Below an authenticated insecure delegation, minimisation continues without pretending that DNSSEC trust has been restored. External authoritative nameserver A/AAAA lookups use the same resolver mode and the same request-scoped minimisation budget.

## Current boundary

This stage does not add an RFC 8020 NXDOMAIN-cut cache, aggressive NSEC/NSEC3 synthesis, parent-side DS minimisation, persistent delegation caching, or minimisation-specific runtime telemetry. Those remain separate resolver/cache milestones.

Production DNS traffic remains outside `internal/gcdns`; no production cutover is part of this source milestone.
