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

The conservative cache partition now includes both `ClientID` and `ClientIP`. This prevents a stable device identity from reusing a split-horizon entry after changing network address or subnet before a future route-aware shared-cache lifecycle is explicitly designed.

Beacon Cache also preserves RFC 9824 Compact Denial semantic metadata (`CompactDenial` and `CompactDenialCO`) through defensive result cloning. It does not permanently rewrite a cached Compact Denial response into one downstream client's preferred RCODE form.

## Beacon Resolver Scheduler

`internal/gcdns/scheduler.go` implements named resolver targets, bounded scheduler concurrency, per-attempt context deadlines, caller cancellation, deterministic failover, health-aware target ordering, latency-aware ordering, and privacy-safe target statistics.

## Beacon Classic DNS Transport

`internal/gcdns/transport.go` provides native classic DNS wire transport. It performs UDP exchanges with an explicit response-size ceiling, retries valid truncated UDP responses over TCP, propagates caller cancellation, applies per-exchange deadlines, and rejects malformed or mismatched responses before they reach resolver logic.

## Beacon Iterative Resolver

`internal/gcdns/iterative.go` provides the native delegation walker. It starts from an approved root/bootstrap endpoint set, clears the recursion-desired bit on authoritative queries, uses the Beacon scheduler for per-delegation failover, sends queries through the DNSExchanger/ClassicTransport boundary, follows NS referrals, derives cache lifetimes from terminal responses, and stops on configured delegation depth or repeated delegation state.

The resolver follows bounded CNAME/DNAME alias chains when a terminal response ends on an alias rather than the requested record type. An unresolved alias target is resolved through a fresh iterative walk and the completed response is merged back under the original question only after the target result is obtained.

Referral processing includes bounded out-of-bailiwick authoritative nameserver discovery. Beacon accepts direct A/AAAA glue only for NS names inside the delegated child, ignores sibling or unrelated Additional-section addresses, and resolves those external NS hostnames through normal recursion instead. Missing mandatory in-domain glue fails closed. External NS address work is request-scoped, cycle-checked, and capped at 32 distinct NS hostname discoveries per top-level resolution.

Beacon also performs RFC 9156 QNAME minimisation for ordinary Internet data queries. It sends a fixed A minimisation QTYPE, reveals one additional QNAME label at a time while locating zone cuts, and shares a request-scoped maximum of 10 minimisation probes across the top-level resolution. Compatibility failures, DNAME, unsupported response forms, or budget exhaustion fall back to the original full question. Parent-side/meta/transfer queries remain on the traditional path in this first stage, and Beacon does not yet use RFC 8020 NXDOMAIN cuts.

## Beacon Resolver Routing

`internal/gcdns/routing.go` implements native forward, conditional, stub, and split-horizon resolver routing while preserving the pipeline order `Policy -> Authoritative DNS -> Cache -> Resolver`.

Routing uses longest DNS-suffix matching. A narrower route therefore overrides a broader route, and an explicit `recursive` route can restore direct recursion below a root or parent forwarding rule. Forward and stub routes use the existing scheduler for bounded target failover; forward targets receive RD=1, while stub targets receive RD=0.

Split-horizon routing can scope a route to exact `ClientID` values, client IP prefixes, or both. For the same DNS suffix, exact client identity outranks network-prefix matches, longer prefixes outrank shorter prefixes, and an unscoped route is the fallback. More-specific DNS namespace matching is evaluated before client-scope specificity.

Routed aliases are re-evaluated under the target name's own route instead of inheriting the previous namespace route. Named route re-entry is cycle-checked. Ambiguous equal-specificity routes fail closed, and target endpoint syntax is validated before construction.

`DelegatingStubResolver` follows bounded subdelegations inside the configured stub namespace. Referrals must move strictly closer to the requested name, remain inside that namespace, and stay within the 16-delegation limit. Required in-domain glue remains fail-closed, sibling Additional data is not trusted as glue, sibling NS names can be resolved only inside the stub namespace, and external NS infrastructure is not silently sent into public recursion. Blank stub namespaces are rejected before FQDN normalization.

`ValidatingDelegatingStubResolver` preserves those transport restrictions while carrying DNSSEC trust from an out-of-band configured private DNSKEY anchor through signed child delegations or authenticated insecure transitions.

`NewRuntimeValidatedRoutingResolver` rejects configured targets that would point back into active GoreeCloud DNS listeners and propagates the same listener boundary to dynamically discovered ordinary and validating delegating-stub child targets. Resolver wrappers cannot hide endpoints from this safety check.

Forwarded and ordinary stub responses clear `AD` and remain `DNSSECIndeterminate` unless a separate local validation layer establishes trust. Explicit GoreeCloud Network/VLAN/group selectors remain staged. The detailed routing boundary is in `docs/resolver-routing.md`.

## Beacon Routed Private DNSSEC Trust Anchors

`PrivateTrustAnchorResolver` adds local terminal validation for an explicitly configured private or otherwise locally administered signed namespace. The DNSKEY trust anchor must be provisioned through an authenticated mechanism outside ordinary DNS resolution and must belong to the exact configured zone.

Beacon forces `CD=1` on the wrapped DNSKEY and terminal lookups so local validation, not the upstream resolver's policy, determines trust. Upstream `AD` is always ignored. The configured DNSKEY must appear in the returned apex DNSKEY RRset and authenticate an RRSIG over that complete RRset before the other apex keys become trusted. Beacon can then use an authenticated ZSK from that keyset to validate terminal RRsets through the existing DNSSEC terminal validator.

The internal CD override is not leaked downstream. After successful local validation Beacon restores the client's original CD bit, keeps AD clear, and sets the normalized DNSSEC result to `DNSSECSecure` only because local validation succeeded.

Private trust-anchor wrappers remain subject to routing self-target protection. Runtime endpoint discovery unwraps the validation layer, and a wrapped `DelegatingStubResolver` receives the runtime listener boundary for dynamically discovered child targets.

`ValidatingDelegatingStubResolver` now extends the private apex anchor through delegated children. For a signed child, the parent-authenticated DS RRset must lead to a matching child DNSKEY, and that DS-authenticated key must validate the complete child apex DNSKEY RRset before Beacon carries the child keyset forward. For an intentionally unsigned child, authenticated NSEC, exact-name NSEC3, or scoped NSEC3 Opt-Out proof must establish DS absence before the branch becomes `DNSSECInsecure`. A missing DS by itself remains insufficient.

After an authenticated insecure transition Beacon skips child DNSKEY acquisition, preserves `DNSSECInsecure` below that boundary, and does not silently restore trust from a deeper DS record. A referral with neither authenticated DS nor authenticated DS-absence proof fails before the child authority is contacted.

The validating private stub keeps the same 16-delegation limit, namespace containment, closer-referral rule, mandatory-glue boundary, same-namespace sibling NS discovery, external-NS refusal, and runtime self-target protection as the ordinary delegating stub. Terminal data on a secure branch must validate with the current authenticated keyset; terminal data on a proven insecure branch is returned as `DNSSECInsecure`.

Ordinary Internet forwarding remains `DNSSECIndeterminate`; upstream AD is never sufficient. The focused boundaries are in `docs/routed-dnssec-policy.md` and `docs/private-stub-dnssec.md`.

## Beacon DNSSEC Foundation

Beacon carries the current root-zone DS trust-anchor set for KSK-2017 and KSK-2024. The validator supports DS-to-DNSKEY authentication, DNSKEY RRset authentication, configured DNSKEY trust-anchor authentication, RRSIG validity-window and cryptographic verification, secure parent-to-child trust carry in both Internet recursion and validating private stubs, terminal positive-RRset validation, CNAME/DNAME alias chains, wildcard-positive validation, wildcard NODATA validation, authenticated NSEC/NSEC3 denial, narrowly scoped NSEC3 Opt-Out insecure-delegation validation, and RFC 9824 Compact Denial of Existence recognition through authenticated NXNAME proof.

Iterative and validating private-stub queries explicitly request DNSSEC material with EDNS and the DO bit. The validating paths use CD where local validation must receive raw DNSSEC material rather than inherit an upstream validation decision. The DNSSEC-validating resolver also advertises RFC 9824 Compact Answers OK upstream through a separate internal capability flag; the plain non-validating iterative resolver does not advertise CO merely because a downstream client did.

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

CO is treated as hop-by-hop state. The normalized `Request.CompactAnswersOK` field records whether the resolver component itself is prepared to consume Compact Answers. The validating iterative resolver and validating private stub set this internal capability for DNSSEC-validation work; plain non-validating paths do not automatically inherit a downstream client's CO bit.

`exchangeResolver` and stub transport helpers set the EDNS CO bit only when `CompactAnswersOK` is true. When a secure terminal response contains NXNAME proof, Beacon records `Result.CompactDenial=true` and preserves the upstream response CO state in `Result.CompactDenialCO` before any downstream presentation occurs.

`Pipeline.Resolve` stores that normalized result before client-specific response restoration. On resolver results and cache hits, `prepareCompactDenialForClient` uses a defensive message copy and renders the response for the current downstream request:

- downstream DO=1, CO=0: NOERROR with authenticated NXNAME proof, response DO set, and response CO clear;
- downstream DO=1, CO=1: NXDOMAIN with authenticated NXNAME proof and response CO set;
- downstream DO=0: NXDOMAIN restoration with Compact-Denial NSEC/NSEC3/RRSIG proof stripped and response CO clear;
- downstream without EDNS: NXDOMAIN restoration without an unsolicited OPT record.

This prevents one client's EDNS flags from contaminating shared Compact Denial cache state, preserves normal downstream DNSSEC filtering, and maintains the RFC 9824 hop-by-hop boundary.

## Beacon CNAME/DNAME alias chains

`internal/gcdns/alias.go` provides shared alias parsing, DNAME substitution, cycle detection, follow-up request construction, merged response handling, and DNSSEC chain-state combination for the plain and validating iterative resolvers and routed resolver composition.

An ordinary CNAME remains a normal RRset and requires its own valid RRSIG in a secure zone. If the original response already contains the requested final RR type after a CNAME chain, Beacon validates the complete returned RRsets without issuing an unnecessary target query. If the response ends on CNAME, the target is resolved separately and the final Answer is merged under the original question.

DNAME handling follows RFC 6672 semantics. DNAME applies to names strictly below its owner, and Beacon selects the closest applicable DNAME. It derives the substituted target deterministically and accepts an unsigned synthesized CNAME only when that CNAME target exactly matches the DNAME substitution and its TTL is either zero or equal to the DNAME TTL. The signed DNAME RRset supplies the DNSSEC authentication for that synthesized CNAME. A mismatched, conflicting, or unexpectedly signed synthesized CNAME fails closed.

Alias processing is capped at 16 transitions. Beacon rejects an alias loop, multiple CNAME records at one owner, conflicting DNAME records, malformed substitutions, and DNS names exceeding protocol length. A zero-TTL alias hop prevents the merged chain from being cached as a fresh combined answer.

The validating iterative resolver starts a fresh root-to-target DNSSEC walk for every unresolved external alias target instead of reusing the prior zone's DNSKEY state. Routed alias processing similarly reselects the resolver for a target name rather than carrying an unrelated private trust anchor across a route boundary. The merged chain is Secure only when every hop is Secure. Bogus or indeterminate hops fail closed; an authenticated insecure hop makes the completed determinate chain Insecure.

Authenticated negative answers are DNAME-aware. A securely validated NSEC or NSEC3 NXDOMAIN proof is rejected if the authenticated closest-encloser bitmap states that an applicable DNAME exists and redirection should have occurred instead of NXDOMAIN.

## Beacon out-of-bailiwick authoritative nameserver discovery

`internal/gcdns/referral_discovery.go` extends referral walking without trusting arbitrary Additional-section address data. A referral is divided into usable in-domain glue, in-domain NS names missing required glue, and sibling or unrelated NS hostnames that require recursive address discovery.

Only syntactically valid A/AAAA data for advertised NS names inside the delegated child is accepted directly as glue. Additional addresses for sibling or unrelated nameservers are ignored even if their owner matches an advertised NS hostname. Those names are resolved through A and AAAA lookups using the same resolver mode as the original request.

Nameserver-address discovery is request-scoped. Successful addresses are reused only within the current top-level resolution, active lookup cycles are rejected, and no more than 32 distinct external NS hostnames may enter discovery. A failed external NS hostname does not prevent another advertised external NS from being tried. If the referral has no usable server and required in-domain glue is missing, resolution fails closed rather than recursively chasing the in-domain NS name and creating a glue dependency loop.

The validating iterative resolver authenticates the parent delegation state before it proceeds below the child and resolves external NS hostnames through the validating path. The validating private stub applies the same distinction within its configured namespace: sibling nameserver addresses may be resolved through the same validating private path, but the resulting IP address identifies transport only and does not authenticate child-zone data.

The focused design record is `docs/out-of-bailiwick-nameserver-discovery.md`. This first implementation performs bounded external NS hostname discovery sequentially and does not create a persistent cross-request infrastructure-address cache.

## Beacon RFC 9156 QNAME minimisation

`internal/gcdns/qname_minimisation.go` and the iterative resolver paths implement Beacon's first QNAME minimisation stage. The resolver uses a fixed A minimisation QTYPE independent of the client's original QTYPE and reveals one additional label from the original QNAME at each probe while locating delegations.

A request-scoped counter limits QNAME minimisation to 10 probes for one top-level resolution. The same `resolutionState` is carried through alias targets and external authoritative nameserver discovery, so those related resolution paths cannot independently reset the minimisation amplification budget. When the budget is exhausted, Beacon continues with the ordinary full-QNAME iterative path.

The first stage uses relaxed compatibility fallback. A minimised exchange error, DNAME response, unsupported response form, or other compatibility condition disables minimisation for that path and sends the original full question. NOERROR, including NODATA or CNAME, advances the minimisation cursor. NXDOMAIN also advances the cursor because Beacon does not yet use RFC 8020 NXDOMAIN cuts. Parent-side DS and selected meta/transfer QTYPEs are excluded until their special minimisation handling is implemented deliberately.

For secure DNSSEC branches, a terminal minimisation response may affect zone-cut discovery only after it authenticates with the currently trusted DNSKEYs. An indeterminate secure-branch probe causes full-query fallback instead of changing trust state. Authenticated referrals continue through the existing DS/DNSKEY chain. Below an authenticated insecure delegation, minimisation continues without restoring nonexistent trust. The detailed boundary is in `docs/qname-minimisation.md`.

## Beacon Wildcard Validation

`internal/gcdns/dnssec_wildcard.go` authenticates wildcard-expanded positive answers and wildcard NODATA responses.

A normal positive RRSIG whose Labels count equals the owner-name label count is accepted without a wildcard denial proof. A literal wildcard owner such as `*.example.test.` remains an exact-owner response even though DNSSEC excludes the leading wildcard label from its RRSIG Labels count.

For an expanded non-wildcard owner with a smaller validated RRSIG Labels count, Beacon derives the generating wildcard's immediate ancestor and next-closer name. NSEC validation requires a signed NSEC interval covering that next-closer name. NSEC3 validation requires a signed non-Opt-Out NSEC3 RR covering the next-closer hash. An authenticated exact/matching denial record for the next-closer instead proves a closer name exists and makes the wildcard expansion bogus.

For empty wildcard NODATA responses, NSEC validation additionally requires the applicable signed wildcard-owner NSEC bitmap to omit both QTYPE and CNAME. NSEC3 validation requires a closest-encloser proof, non-Opt-Out next-closer hash coverage, and a signed NSEC3 RR matching the wildcard owner whose bitmap omits QTYPE and CNAME.

A valid wildcard RRset signature or wildcard type bitmap without the required no-closer-match proof is not enough to return `DNSSECSecure`.

## Corrected compact-denial development path

A short-lived branch-only experiment used the phrase "compact NSEC NXDOMAIN" for logic that inferred nonexistent ancestors from NSEC coverage and treated the authenticated DNSKEY zone apex as an implicit closest encloser. Standards review showed that this was not RFC 9824 Compact Denial and was unsafe as a general validator rule because Empty Non-Terminal and DNAME/delegation state could be missed. The experimental source, tests, and unfinished gate were removed before CI integration or acceptance. Branch history was preserved; no force rewrite was performed.

## Security boundary

The native foundation currently enforces source-level invariants for DNSSEC validation, DNS rebinding protection, explicit recursion and administration ACLs, no accidental open recursion, bogus-result rejection before cache insertion, bounded cache/scheduler/transport behavior, delegation depth and loop protection, alias-loop protection, request-scoped out-of-bailiwick nameserver discovery, mandatory in-domain glue handling, RFC 9156 QNAME minimisation with a request-scoped 10-probe bound and DNSSEC-authenticated secure minimisation responses, longest-suffix resolver routing, client/subnet split-horizon selection, route-loop and ambiguity rejection, client-identity-plus-address cache partitioning, forward/stub target failover, explicit RD behavior, active-listener self-target rejection for configured and dynamically discovered stub targets, forward/stub AD clearing with `DNSSECIndeterminate`, private DNSKEY trust-anchor authentication with forced upstream CD and downstream CD restoration, private parent-DS to child-DNSKEY trust carry, authenticated private insecure-delegation transitions, root trust anchors, DS/DNSKEY authentication, terminal positive RRset validation, CNAME/DNAME alias chains including signed DNAME coverage of a synthesized CNAME, wildcard-positive no-closer-match validation, wildcard NODATA validation, NSEC/NSEC3 insecure-delegation proof including scoped Opt-Out DS-absence transitions, exact-owner NSEC/NSEC3 NODATA proof, conventional NSEC/NSEC3 NXDOMAIN proof with DNAME conflict checks, RFC 9824 NXNAME compact-denial recognition, validating-resolver CO signaling, and per-client cache-aware Compact Denial response restoration.

These are development controls, not production acceptance evidence.

## Production boundary

No production traffic is routed through `internal/gcdns` yet. Existing AdGuard Home and Unbound runtime behavior remains unchanged until the native path has executable parity, tests, security validation, migration procedures, rollback procedures, and explicit production acceptance.

## Next implementation sequence

1. Define general Internet forwarding validation policy without trusting upstream AD.
2. Add DNSSEC algorithm/digest policy and trust-anchor lifecycle/rollover automation.
3. Add persistent cache, prefetch/auto-prefetch, encrypted DNS, authoritative DNS, filtering, DHCP, clustering, APIs, identity, and Glaze UI administration.
4. Validate the competitive-superset requirement with feature, security, privacy, control, resilience, and operational acceptance matrices.
5. Perform controlled migration and production replacement only after GoreeCloud release and production-readiness gates pass.
