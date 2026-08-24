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

The conservative cache partition includes both `ClientID` and `ClientIP`. This prevents a stable device identity from reusing a split-horizon entry after changing network address or subnet before a future route-aware shared-cache lifecycle is explicitly designed.

Beacon Cache also preserves RFC 9824 Compact Denial semantic metadata (`CompactDenial` and `CompactDenialCO`) through defensive result cloning. It does not permanently rewrite a cached Compact Denial response into one downstream client's preferred RCODE form.

## Beacon Resolver Scheduler

`internal/gcdns/scheduler.go` implements named resolver targets, bounded scheduler concurrency, per-attempt context deadlines, caller cancellation, deterministic failover, health-aware target ordering, latency-aware ordering, and privacy-safe target statistics.

## Beacon Classic DNS Transport

`internal/gcdns/transport.go` provides native classic DNS wire transport. It performs UDP exchanges with an explicit response-size ceiling, retries valid truncated UDP replies over TCP, propagates caller cancellation, applies per-exchange deadlines, and rejects malformed or mismatched responses before they reach resolver logic.

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

`NewRuntimeValidatedRoutingResolver` rejects configured targets that would point back into active GoreeCloud DNS listeners and propagates the same listener boundary to dynamically discovered ordinary and validating delegating-stub child targets. Resolver wrappers cannot hide endpoints from this safety check. `ValidatingForwardingResolver` also exposes its underlying configured forwarder endpoints to this validation boundary.

Raw forwarded and ordinary stub responses clear `AD` and remain `DNSSECIndeterminate`. Local validation is supplied only by an explicit validating resolver wrapper. Explicit GoreeCloud Network/VLAN/group selectors remain staged. The detailed routing boundary is in `docs/resolver-routing.md`.

## Beacon Locally Validating Forwarding

`ValidatingForwardingResolver` allows GoreeCloud DNS to use recursive forwarding servers as transports while keeping DNSSEC trust decisions local to Beacon.

The public constructor uses the built-in root DS trust-anchor set. Forwarded terminal data and validation-support queries are sent with RD=1, DO enabled, and CD=1. Beacon ignores and clears upstream AD rather than accepting the forwarding server's validation assertion.

For signed forwarded data, Beacon derives the authoritative signer zone from the RRSIG Signer Name and builds trust only to that zone. Starting with an authenticated root DNSKEY RRset, it validates each secure DS-to-DNSKEY transition. When an intermediate name is not a delegation, Beacon requires authenticated exact-name NSEC or non-Opt-Out NSEC3 DS-NODATA proof before retaining the current parent keyset and continuing toward a deeper signer zone.

If authenticated denial proves that a real delegation has no DS, the chain becomes `DNSSECInsecure`. A missing DS alone is insufficient, and a deeper DS cannot silently restore trust below the authenticated insecure boundary. Unsupported or unproven DS state fails closed.

DS remains parent-side data. When a downstream client asks for DS, Beacon stops the trust walk at the parent and validates the returned DS RRset with the authenticated parent DNSKEY set rather than crossing into the child first.

Recursive forwarders may return a complete CNAME or DNAME chain spanning multiple zones. Beacon isolates and authenticates the current alias link, then performs a fresh locally validating forwarded lookup for the target instead of trusting target-zone data under source-zone keys. The existing 16-transition alias bound and weakest-link DNSSEC state combination remain active.

The forwarding trust walk is bounded to 128 labels. Multiple signer zones inside one non-alias response fragment fail closed rather than being resolved heuristically. Raw `ForwardingResolver` remains available as an explicitly non-validating transport and continues to return `DNSSECIndeterminate`.

The focused design and current proof limitations are in `docs/validating-forwarding.md`.

## Beacon Routed Private DNSSEC Trust Anchors

`PrivateTrustAnchorResolver` adds local terminal validation for an explicitly configured private or otherwise locally administered signed namespace. The DNSKEY trust anchor must be provisioned through an authenticated mechanism outside ordinary DNS resolution and must belong to the exact configured zone.

Beacon forces `CD=1` on the wrapped DNSKEY and terminal lookups so local validation, not the upstream resolver's policy, determines trust. Upstream `AD` is always ignored. The configured DNSKEY must appear in the returned apex DNSKEY RRset and authenticate an RRSIG over that complete RRset before the other apex keys become trusted. Beacon can then use an authenticated ZSK from that keyset to validate terminal RRsets through the existing DNSSEC terminal validator.

The internal CD override is not leaked downstream. After successful local validation Beacon restores the client's original CD bit, keeps AD clear, and sets the normalized DNSSEC result to `DNSSECSecure` only because local validation succeeded.

Private trust-anchor wrappers remain subject to routing self-target protection. Runtime endpoint discovery unwraps the validation layer, and a wrapped `DelegatingStubResolver` receives the runtime listener boundary for dynamically discovered child targets.

`ValidatingDelegatingStubResolver` extends the private apex anchor through delegated children. For a signed child, the parent-authenticated DS RRset must lead to a matching child DNSKEY, and that DS-authenticated key must validate the complete child apex DNSKEY RRset before Beacon carries the child keyset forward. For an intentionally unsigned child, authenticated NSEC, exact-name NSEC3, or scoped NSEC3 Opt-Out proof must establish DS absence before the branch becomes `DNSSECInsecure`. A missing DS by itself remains insufficient.

After an authenticated insecure transition Beacon skips child DNSKEY acquisition, preserves `DNSSECInsecure` below that boundary, and does not silently restore trust from a deeper DS record. A referral with neither authenticated DS nor authenticated DS-absence proof fails before the child authority is contacted.

The validating private stub keeps the same 16-delegation limit, namespace containment, closer-referral rule, mandatory-glue boundary, same-namespace sibling NS discovery, external-NS refusal, and runtime self-target protection as the ordinary delegating stub. Terminal data on a secure branch must validate with the current authenticated keyset; terminal data on a proven insecure branch is returned as `DNSSECInsecure`.

The focused private trust boundaries are in `docs/routed-dnssec-policy.md` and `docs/private-stub-dnssec.md`.

## Beacon DNSSEC Foundation

Beacon carries the current root-zone DS trust-anchor set for KSK-2017 and KSK-2024. The validator supports DS-to-DNSKEY authentication, DNSKEY RRset authentication, configured DNSKEY trust-anchor authentication, RRSIG validity-window and cryptographic verification, secure parent-to-child trust carry in Internet recursion, locally validating forwarding, and validating private stubs, terminal positive-RRset validation, CNAME/DNAME alias chains, wildcard-positive validation, wildcard NODATA validation, authenticated NSEC/NSEC3 denial, narrowly scoped NSEC3 Opt-Out insecure-delegation validation, and RFC 9824 Compact Denial of Existence recognition through authenticated NXNAME proof.

Iterative, validating-forwarding, and validating-private-stub paths request DNSSEC material with EDNS and the DO bit. Routed validating paths set CD where local validation must receive raw DNSSEC material rather than inherit an upstream validation decision. The DNSSEC-validating paths may advertise RFC 9824 Compact Answers OK internally when they are prepared to consume Compact Answers; plain non-validating paths do not advertise CO merely because a downstream client did.

### DNSSEC algorithm and digest policy

`internal/gcdns/dnssec_algorithm_policy.go` makes validation policy explicit rather than inheriting every algorithm exposed by the underlying DNS library. `scripts/validate_dnssec_algorithm_policy.py` is the focused fail-closed source gate, and the `beacon-native-core` CI job runs it before `go test ./internal/gcdns`.

Beacon currently accepts RSASHA1, RSASHA1-NSEC3-SHA1, RSASHA256, RSASHA512, ECDSAP256SHA256, ECDSAP384SHA384, and ED25519 for legacy/current RRSIG and DNSKEY validation where the implementation exists. RSASHA1 and RSASHA1-NSEC3-SHA1 are not accepted to establish a DS delegation; a delegation containing only those SHA-1 signing algorithms is classified `DNSSECInsecure` in accordance with the current transition policy. If an accepted modern DS is also present, its cryptographic result remains authoritative and cannot be silently downgraded to insecure by the SHA-1 record.

DS digest validation supports SHA-1, SHA-256, and SHA-384. Unsupported algorithms or digest families are kept explicit and fail closed or remain indeterminate according to whether usable validation material remains. Ed448 and other newer/MAY algorithms are not treated as implemented merely because they exist in a registry; cryptographic implementation and deterministic acceptance tests are required first.

DNSSEC key-size policy is still a separate unfinished part of this milestone.

## Beacon NSEC Authenticated Denial

`internal/gcdns/dnssec_nsec.go` provides the conventional unhashed authenticated-denial layer.

Implemented behavior includes:

- signed exact-owner NSEC proof for an intentionally unsigned child delegation;
- requirement that the delegation proof advertise NS, omit DS, and not represent an SOA-bearing zone apex;
- preservation of `DNSSECInsecure` below a proven unsigned delegation;
- skipping child DNSKEY retrieval after an insecure delegation has been authenticated;
- signed exact-owner NSEC NODATA validation when the bitmap omits the requested type and CNAME;
- DNSSEC canonical-name interval processing, including NSEC wrap-around intervals;
- conservative empty-answer NXDOMAIN validation requiring authenticated closest-encloser evidence, a covering NSEC for the next-closer name, and a covering NSEC for the corresponding wildcard;
- authenticated-zone boundary checks for NXDOMAIN proof material; and
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
- rejection when an NXDOMAIN proof contains the queried owner hash; and
- fail-closed rejection of inconsistent parameters, out-of-zone proof owners, unsupported hash algorithms or flags, malformed signatures, contradictory DS state, missing referral evidence, and missing Opt-Out coverage where the omitted-delegation proof requires it.

Opt-Out support is deliberately restricted to authenticating DS absence at an actual delegation boundary. Generic terminal NODATA, NXDOMAIN, wildcard-positive, and wildcard-NODATA validation continue to reject Opt-Out proof sets because Opt-Out coverage does not generally authenticate whether every covered insecure delegation exists or does not exist.

The terminal validator tries NSEC first and only falls through to NSEC3 when the NSEC path is genuinely indeterminate. Delegation authentication follows the same fail-closed ordering. Bogus NSEC evidence is never bypassed by falling through to NSEC3.

## RFC 9824 Compact Denial of Existence

`internal/gcdns/dnssec_compact_denial.go` implements Beacon's resolver-side RFC 9824 Compact Denial boundary.

RFC 9824 Compact Answers represent a nonexistent name through authenticated NXNAME proof. For the normal form, the response uses NOERROR and an empty Answer section. A response using NXDOMAIN is accepted as Compact Denial only when the response also carries the RFC 9824 Compact Answers OK (CO) flag.

For NSEC, the owner must match QNAME and the Type Bit Maps field must contain exactly RRSIG, NSEC, and NXNAME. For NSEC3, the proof must match QNAME and its Type Bit Maps field must contain exactly NXNAME. The proof RRset must validate against authenticated zone DNSKEY material. Malformed NXNAME responses fail closed rather than being treated as ordinary NODATA or conventional NXDOMAIN.

Ordinary NODATA and Empty Non-Terminal responses without NXNAME remain on the existing NODATA path. Conventional NXDOMAIN responses without NXNAME remain on the existing NSEC/NSEC3 NXDOMAIN path. Explicit NXNAME queries are rejected locally with FORMERR before iterative network work because NXNAME is a Meta-TYPE and is not a normal resolvable RR type.

## RFC 9824 Compact Answers OK hop-by-hop handling

CO is treated as hop-by-hop state. The normalized `Request.CompactAnswersOK` field records whether the resolver component itself is prepared to consume Compact Answers. Validating iterative, validating forwarding, and validating private-stub paths can set this internal capability for DNSSEC-validation work; plain non-validating paths do not automatically inherit a downstream client's CO bit.

When a secure terminal response contains NXNAME proof, Beacon records `Result.CompactDenial=true` and preserves the upstream response CO state in `Result.CompactDenialCO` before any downstream presentation occurs.

`Pipeline.Resolve` stores that normalized result before client-specific response restoration. On resolver results and cache hits, `prepareCompactDenialForClient` uses a defensive message copy and renders the response for the current downstream request:

- downstream DO=1, CO=0: NOERROR with authenticated NXNAME proof, response DO set, and response CO clear;
- downstream DO=1, CO=1: NXDOMAIN with authenticated NXNAME proof and response CO set;
- downstream DO=0: NXDOMAIN restoration with Compact-Denial NSEC/NSEC3/RRSIG proof stripped and response CO clear; and
- downstream without EDNS: NXDOMAIN restoration without an unsolicited OPT record.

This prevents one client's EDNS flags from contaminating shared Compact Denial cache state, preserves normal downstream DNSSEC filtering, and maintains the RFC 9824 hop-by-hop boundary.

## Beacon CNAME/DNAME alias chains

`internal/gcdns/alias.go` implements bounded CNAME/DNAME chain planning and response merging for plain and DNSSEC-validating iterative resolution.

The planner rejects malformed owner state, multiple CNAMEs at one owner, more than one applicable DNAME, alias cycles, names longer than the DNS wire limit, and chains longer than 16 transitions. CNAME owners cannot coexist with other ordinary data at the same owner. DNAME applies only to strict descendants; the closest applicable DNAME is selected and its substitution target must remain a valid DNS name.

For DNSSEC, each CNAME RRset must be signed unless it is the exact CNAME synthesized from a securely signed DNAME under RFC 6672. An unsigned synthesized CNAME is accepted only when its owner/target derivation exactly matches the DNAME and its TTL is zero or equal to the DNAME TTL. A signed synthesized CNAME, target mismatch, TTL mismatch, or otherwise malformed chain fails closed.

The validating resolver restarts trust establishment for each unresolved alias target rather than carrying keys from the previous signer zone across the alias boundary. A completed chain is `DNSSECSecure` only if every hop is secure. A bogus or indeterminate hop fails closed; an authenticated insecure hop makes the determinate completed chain insecure.

Because the merged result spans separately resolved messages, its cache lifetime is forced to zero until a dedicated alias-aware multi-response cache contract exists.

Authenticated NSEC/NSEC3 NXDOMAIN validation also rejects denial proof when the authenticated closest-encloser bitmap proves a DNAME exists that should have redirected the query.

The focused alias contract is in `docs/dnssec-alias-chains.md`.

## Beacon Out-of-Bailiwick Nameserver Discovery

`internal/gcdns/referral.go` and the iterative resolver paths support bounded authoritative nameserver address discovery when a referral names NS hosts outside the delegated child.

Direct A/AAAA Additional-section addresses are accepted only for advertised NS hostnames inside the delegated child. Sibling Additional records and unrelated addresses are ignored instead of being treated as trusted glue. Missing mandatory in-domain glue fails closed because recursively resolving an in-domain NS address through the same unresolved delegation would create a glue dependency loop.

Advertised external NS hostnames are resolved through normal A and AAAA recursion using the same resolver mode as the originating request. Discovery is request-scoped, cycle-checked, caches successful addresses only inside that top-level request, and allows at most 32 distinct NS hostname discoveries before failing closed. Failure resolving one external NS name does not prevent attempting another advertised external NS name.

The validating iterative resolver performs this auxiliary address work through the validating path. Discovered IP addresses are transport endpoints only; they do not establish DNSSEC trust. Parent DS authentication, child DNSKEY authentication, and terminal RRset validation remain the trust boundary.

## Beacon QNAME minimisation

`internal/gcdns/qname_minimisation.go` implements the current RFC 9156 minimisation boundary.

For eligible ordinary Internet data queries, Beacon sends an A minimisation QTYPE and reveals one additional QNAME label per probe while discovering zone cuts. A shared request-scoped budget permits at most 10 minimisation probes across the top-level resolution, alias targets, and external NS-address discovery. Exhausting the budget falls back to the normal full original question rather than failing the DNS request solely because minimisation cannot continue.

Referral probes use the same conservative glue and external-NS discovery path. NOERROR, including NODATA and CNAME, advances the cursor; DNAME, exchange or compatibility failure, and unsupported response forms fall back to the full question. The first implementation does not use RFC 8020 NXDOMAIN cuts and excludes DS plus selected parent-side/meta/transfer QTYPEs from minimisation.

On DNSSEC-secure branches, a non-referral minimisation response must authenticate against the current trusted DNSKEY set before its zone-cut information may be used. An indeterminate secure probe triggers full-query fallback. Secure referrals retain the normal DS/DNSKEY transition, and authenticated insecure branches cannot regain secure trust through minimisation. When the last minimised A probe is already the client's exact original A question, Beacon can reuse that response instead of issuing a duplicate full query.

## Security boundary

The native foundation currently enforces source-level invariants for DNSSEC validation, explicit DNSSEC algorithm/digest handling, DNS rebinding protection, explicit recursion and administration ACLs, no accidental open recursion, bogus-result rejection before cache insertion, bounded cache/scheduler/transport behavior, delegation depth and loop protection, alias-loop protection, request-scoped out-of-bailiwick nameserver discovery, mandatory in-domain glue handling, RFC 9156 QNAME minimisation with a request-scoped 10-probe bound and DNSSEC-authenticated secure minimisation responses, longest-suffix resolver routing, client/subnet split-horizon selection, route-loop and ambiguity rejection, client-identity-plus-address cache partitioning, forward/stub target failover, explicit RD behavior, active-listener self-target rejection for configured and dynamically discovered stub targets, raw forward/stub AD clearing with `DNSSECIndeterminate`, root-anchored locally validating forwarding with CD and upstream-AD non-trust, signer-zone trust discovery, parent-side DS handling, authenticated non-delegation DS-NODATA proof, private DNSKEY trust-anchor authentication with forced upstream CD and downstream CD restoration, private parent-DS to child-DNSKEY trust carry, authenticated Internet and private insecure-delegation transitions, root trust anchors, DS/DNSKEY authentication, terminal positive RRset validation, CNAME/DNAME alias chains including signed DNAME coverage of a synthesized CNAME, wildcard-positive no-closer-match validation, wildcard NODATA validation, NSEC/NSEC3 insecure-delegation proof including scoped Opt-Out DS-absence transitions, exact-owner NSEC/NSEC3 NODATA proof, conventional NSEC/NSEC3 NXDOMAIN proof with DNAME conflict checks, RFC 9824 NXNAME compact-denial recognition, validating-resolver CO signaling, and per-client cache-aware Compact Denial response restoration.

These are development controls, not production acceptance evidence.

## Production boundary

No production traffic is routed through `internal/gcdns` yet. Existing AdGuard Home and Unbound runtime behavior remains unchanged until the native path has executable parity, tests, security validation, migration procedures, rollback procedures, and explicit production acceptance.

## Next implementation sequence

1. Complete DNSSEC key-size policy; algorithm/digest source policy and its CI gate are now present.
2. Add authenticated trust-anchor persistence, update approval, rollover automation, and reusable validation-state/cache lifecycle.
3. Broaden locally validating forwarding only where additional standards-backed non-delegation or Empty Non-Terminal denial forms can be authenticated safely, and add approved encrypted forwarding transports.
4. Add persistent cache, prefetch/auto-prefetch, encrypted DNS listeners, authoritative DNS, filtering, DHCP, clustering, APIs, identity, and Glaze UI administration.
5. Validate the competitive-superset requirement with feature, security, privacy, control, resilience, and operational acceptance matrices.
6. Perform controlled migration and production replacement only after GoreeCloud release and production-readiness gates pass.
