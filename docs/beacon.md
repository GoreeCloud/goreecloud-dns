# GoreeCloud Beacon

GoreeCloud Beacon is the official feature umbrella for the first-party capabilities of GoreeCloud DNS.

GoreeCloud DNS remains the application and service name. Beacon is not a separate daemon, product, or deployment boundary.

## Native resolver transition

The first executable Beacon foundation lives in `internal/gcdns` and is intentionally isolated from the inherited AdGuard Home production request path.

The native pipeline is:

`Policy -> Authoritative DNS -> Cache -> Resolver`

The contracts are designed so first-party caching, recursive resolution, forwarding, authoritative DNS, DNSSEC validation, filtering, observability, encrypted DNS, DHCP, clustering, and administration can be introduced incrementally without recreating a permanent AdGuard Home/Unbound split.

## Competitive direction

GoreeCloud DNS targets a stable capability superset of Technitium DNS Server, Pi-hole, and AdGuard Home in useful DNS features while aiming to exceed those references in privacy-by-default behavior, security boundaries, operator control, resilience, observability, recovery, GoreeCloud integration, and first-party ownership. This is a product requirement, not a claim that every target capability is already implemented.

## Beacon Cache

`internal/gcdns/cache.go` provides a sharded, concurrency-safe bounded in-memory DNS cache with TTL expiration and wire-TTL aging, negative-response accounting, optional bounded serve-stale behavior, defensive DNS message copies, client-aware cache partitioning, serialized whole-cache flushes, and privacy-safe runtime statistics.

Beacon Cache also preserves RFC 9824 Compact Denial semantic metadata (`CompactDenial` and `CompactDenialCO`) through defensive result cloning. It does not permanently rewrite a cached Compact Denial response into one downstream client's preferred RCODE form.

## Beacon Resolver Scheduler

`internal/gcdns/scheduler.go` implements named resolver targets, bounded scheduler concurrency, per-attempt context deadlines, caller cancellation, deterministic failover, health-aware target ordering, latency-aware ordering, and privacy-safe target statistics.

## Beacon Classic DNS Transport

`internal/gcdns/transport.go` provides native classic DNS wire transport. It performs UDP exchanges with an explicit response-size ceiling, retries valid truncated UDP responses over TCP, propagates caller cancellation, applies per-exchange deadlines, and rejects malformed or mismatched responses before they reach resolver logic.

## Beacon Iterative Resolver

`internal/gcdns/iterative.go` provides the native delegation walker. It starts from an approved root/bootstrap endpoint set, clears the recursion-desired bit on authoritative queries, uses the Beacon scheduler for per-delegation failover, sends queries through the DNSExchanger/ClassicTransport boundary, follows NS referrals, derives cache lifetimes from terminal responses, and stops on configured delegation depth or repeated delegation state.

Referral processing remains conservative: only advertised in-bailiwick glue is accepted. Out-of-bailiwick nameserver address discovery remains a later resolver milestone.

## Beacon DNSSEC Foundation

Beacon carries the current root-zone DS trust-anchor set for KSK-2017 and KSK-2024. The validator supports DS-to-DNSKEY authentication, DNSKEY RRset authentication, RRSIG validity-window and cryptographic verification, secure parent-to-child trust carry, terminal positive-RRset validation, wildcard-positive validation, wildcard NODATA validation, authenticated NSEC/NSEC3 denial, narrowly scoped NSEC3 Opt-Out insecure-delegation validation, and RFC 9824 Compact Denial of Existence recognition through authenticated NXNAME proof.

Iterative queries explicitly request DNSSEC material with EDNS and the DO bit. The DNSSEC-validating resolver also advertises RFC 9824 Compact Answers OK upstream through a separate internal capability flag; the plain non-validating iterative resolver does not advertise CO merely because a downstream client did.

## Beacon NSEC Authenticated Denial

`internal/gcdns/dnssec_nsec.go` provides the conventional unhashed authenticated-denial layer.

Implemented behavior includes:

- signed exact-owner NSEC proof for an intentionally unsigned child delegation;
- requirement that the delegation proof advertises NS, omits DS, and does not represent an SOA-bearing zone apex;
- preservation of `DNSSECInsecure` below a proven unsigned delegation;
- skipping child DNSKEY retrieval after an insecure delegation has been authenticated;
- signed exact-owner NSEC NODATA validation when the bitmap omits the requested type and CNAME;
- DNSSEC canonical-name interval processing, including NSEC wrap-around intervals;
- conservative empty-answer NXDOMAIN validation requiring authenticated closest-encloser evidence, a covering NSEC for the next-closer name, and a covering NSEC for the corresponding wildcard;
- authenticated-zone boundary checks for NXDOMAIN proof material;
- fail-closed behavior for unsigned, invalid, malformed, or unproven denial material.

Beacon does not infer that an ancestor fails to exist merely because it lacks an exact NSEC owner. Empty Non-Terminal names can exist without ordinary RRsets, and DNAME or delegation state at ancestors must not be skipped by optimistic closest-encloser inference.

RFC 4470 minimally covering NSEC records remain conventional NSEC material to the validator and do not create a special NXDOMAIN trust shortcut.

## Beacon NSEC3 Authenticated Denial

`internal/gcdns/dnssec_nsec3.go` adds the hashed authenticated-denial path used by DNSSEC zones that publish NSEC3.

Implemented behavior includes:

- signed exact-name NSEC3 NODATA validation when the bitmap omits the requested type and CNAME;
- NSEC3 NXDOMAIN validation using an authenticated closest encloser, next-closer hash coverage, and wildcard hash coverage;
- exact-name NSEC3 proof for intentionally unsigned delegated children when NS is present, DS is absent, and the proof is not SOA-bearing apex data;
- scoped RFC 5155 Opt-Out validation for an insecure delegation omitted from the NSEC3 chain: the referral must contain an actual NS RRset at the child, the closest provable encloser must authenticate, an NSEC3 RR must cover the child's next-closer name, and that covering record must have Opt-Out set;
- exact matching delegation NSEC3 records may carry Opt-Out because their authenticated owner hash and bitmap still establish the delegation itself;
- consistent NSEC3 hash algorithm, iteration, salt, hash-length, and authenticated-zone ownership checks across the proof set;
- cryptographic RRSIG validation of every NSEC3 RRset relied on by a proof;
- rejection when an NXDOMAIN proof contains the queried owner hash;
- fail-closed rejection of inconsistent parameters, out-of-zone proof owners, unsupported hash algorithms or flags, malformed signatures, contradictory DS state, missing referral evidence, and missing Opt-Out coverage where the omitted-delegation proof requires it.

Opt-Out support is deliberately restricted to authenticating DS absence at an actual delegation boundary. Generic terminal NODATA, NXDOMAIN, wildcard-positive, and wildcard-NODATA validation continue to reject Opt-Out proof sets because Opt-Out coverage does not generally authenticate whether every covered insecure delegation exists or does not exist.

The terminal validator tries NSEC first and only falls through to NSEC3 when the NSEC path is genuinely indeterminate. Delegation authentication follows the same fail-closed ordering. Bogus NSEC evidence is never bypassed by falling through to NSEC3.

## RFC 9824 Compact Denial of Existence

`internal/gcdns/dnssec_compact_denial.go` implements Beacon's resolver-side RFC 9824 Compact Denial boundary.

RFC 9824 Compact Answers represent a nonexistent name through authenticated NXNAME proof. For the normal form, the response uses NOERROR and an empty Answer section. A response using NXDOMAIN is accepted as Compact Denial only when the response also carries the RFC 9824 Compact Answers OK (CO) flag.

For NSEC, the owner must match QNAME and the Type Bit Maps field must contain exactly RRSIG, NSEC, and NXNAME. For NSEC3, the proof must match QNAME and its Type Bit Maps field must contain exactly NXNAME. The proof RRset must validate against authenticated zone DNSKEY material. Malformed NXNAME responses fail closed rather than being treated as ordinary NODATA or conventional NXDOMAIN.

Ordinary NODATA and Empty Non-Terminal responses without NXNAME remain on the existing NODATA path. Conventional NXDOMAIN responses without NXNAME remain on the existing NSEC/NSEC3 NXDOMAIN path. Explicit NXNAME queries are rejected locally with FORMERR before iterative network work because NXNAME is a Meta-TYPE and is not a normal resolvable RR type.

## RFC 9824 Compact Answers OK hop-by-hop handling

CO is treated as hop-by-hop state. The normalized `Request.CompactAnswersOK` field records whether the resolver component itself is prepared to consume Compact Answers. The validating iterative resolver sets this capability for its upstream authority/DNSKEY work. The plain iterative resolver does not automatically inherit a downstream client's CO bit.

`exchangeResolver` sets the EDNS CO bit only when `CompactAnswersOK` is true. When a secure terminal response contains NXNAME proof, the validating resolver records `Result.CompactDenial=true` and preserves the upstream response CO state in `Result.CompactDenialCO` before any downstream presentation occurs.

`Pipeline.Resolve` stores that normalized result before client-specific response restoration. On resolver results and cache hits, `prepareCompactDenialForClient` uses a defensive message copy and renders the response for the current downstream request:

- downstream DO=1, CO=0: NOERROR with authenticated NXNAME proof, response DO set, and response CO clear;
- downstream DO=1, CO=1: NXDOMAIN with authenticated NXNAME proof and response CO set;
- downstream DO=0: NXDOMAIN restoration with Compact-Denial NSEC/NSEC3/RRSIG proof stripped and response CO clear;
- downstream without EDNS: NXDOMAIN restoration without an unsolicited OPT record.

This prevents one client's EDNS flags from contaminating shared Compact Denial cache state, preserves normal downstream DNSSEC filtering, and maintains the RFC 9824 hop-by-hop boundary.

## Beacon Wildcard Validation

`internal/gcdns/dnssec_wildcard.go` authenticates wildcard-expanded positive answers and wildcard NODATA responses.

A normal positive RRSIG whose Labels count equals the owner-name label count is accepted without a wildcard denial proof. A literal wildcard owner such as `*.example.test.` remains an exact-owner response even though DNSSEC excludes the leading wildcard label from its RRSIG Labels count.

For an expanded non-wildcard owner with a smaller validated RRSIG Labels count, Beacon derives the generating wildcard's immediate ancestor and next-closer name. NSEC validation requires a signed NSEC interval covering that next-closer name. NSEC3 validation requires a signed non-Opt-Out NSEC3 RR covering the next-closer hash. An authenticated exact/matching denial record for the next-closer instead proves a closer name exists and makes the wildcard expansion bogus.

For empty wildcard NODATA responses, NSEC validation additionally requires the applicable signed wildcard-owner NSEC bitmap to omit both QTYPE and CNAME. NSEC3 validation requires a closest-encloser proof, non-Opt-Out next-closer hash coverage, and a signed NSEC3 RR matching the wildcard owner whose bitmap omits QTYPE and CNAME.

A valid wildcard RRset signature or wildcard type bitmap without the required no-closer-match proof is not enough to return `DNSSECSecure`.

## Corrected compact-denial development path

A short-lived branch-only experiment used the phrase "compact NSEC NXDOMAIN" for logic that inferred nonexistent ancestors from NSEC coverage and treated the authenticated DNSKEY zone apex as an implicit closest encloser. Standards review showed that this was not RFC 9824 Compact Denial and was unsafe as a general validator rule because Empty Non-Terminal and DNAME/delegation state could be missed. The experimental source, tests, and unfinished gate were removed before CI integration or acceptance. Branch history was preserved; no force rewrite was performed.

## Security boundary

The native foundation currently enforces source-level invariants for DNSSEC validation, DNS rebinding protection, explicit recursion and administration ACLs, no accidental open recursion, bogus-result rejection before cache insertion, bounded cache/scheduler/transport behavior, delegation depth and loop protection, in-bailiwick glue acceptance, root trust anchors, DS/DNSKEY authentication, terminal positive RRset validation, wildcard-positive no-closer-match validation, wildcard NODATA validation, NSEC/NSEC3 insecure-delegation proof including scoped Opt-Out DS-absence transitions, exact-owner NSEC/NSEC3 NODATA proof, conventional NSEC/NSEC3 NXDOMAIN proof, RFC 9824 NXNAME compact-denial recognition, validating-resolver CO signaling, and per-client cache-aware Compact Denial response restoration.

These are development controls, not production acceptance evidence.

## Production boundary

No production traffic is routed through `internal/gcdns` yet. Existing AdGuard Home and Unbound runtime behavior remains unchanged until the native path has executable parity, tests, security validation, migration procedures, rollback procedures, and explicit production acceptance.

## Next implementation sequence

1. Complete signed CNAME/DNAME chain handling and out-of-bailiwick nameserver discovery.
2. Implement QNAME minimization, forward/conditional/stub routing, and split-horizon routing.
3. Add persistent cache, prefetch/auto-prefetch, encrypted DNS, authoritative DNS, filtering, DHCP, clustering, APIs, identity, and Glaze UI administration.
4. Validate the competitive-superset requirement with feature, security, privacy, control, resilience, and operational acceptance matrices.
5. Perform controlled migration and production replacement only after GoreeCloud release and production-readiness gates pass.
