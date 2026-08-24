# Beacon Iterative DNSSEC Validation

GoreeCloud DNS has a validating iterative resolver in `internal/gcdns/iterative_dnssec.go`, a locally validating forwarding path in `internal/gcdns/validating_forwarding.go`, and a private validating stub path in `internal/gcdns/validating_stub_subdelegation.go`.

## Current trust flow

The validating Internet path performs these steps before a secure answer may be returned:

1. Query the root zone for DNSKEY material with DNSSEC signaling enabled.
2. Authenticate the root DNSKEY RRset against the carried GoreeCloud Beacon root DS trust anchors.
3. Use RFC 9156 QNAME minimisation probes to locate zone cuts without exposing the full original QNAME prematurely when direct iterative recursion is selected; secure non-referral probes must authenticate before they may advance the minimisation cursor.
4. Authenticate each signed child DS RRset with the currently trusted parent DNSKEY set.
5. Obtain and authenticate each child DNSKEY RRset against the authenticated child DS RRset before carrying the child keys forward.
6. When DS is absent, accept an insecure child only when signed NSEC, exact-name NSEC3, or the narrowly scoped NSEC3 Opt-Out delegation proof described below authenticates the secure-to-insecure transition.
7. Once an insecure delegation is authenticated, preserve `DNSSECInsecure` below that boundary instead of attempting to recreate trust without another configured trust anchor.
8. For a positive terminal response, validate every applicable RRset against matching RRSIG material using the authenticated DNSKEY set for the answering zone.
9. If a validated positive RRSIG has fewer `RRSIG Labels` than its expanded owner name, require authenticated wildcard no-closer-match proof.
10. For CNAME or DNAME redirection, validate the alias link, resolve the target through an independently trusted path, and combine the chain only after every hop reaches a determinate DNSSEC state.
11. For an empty response carrying NXNAME, validate RFC 9824 Compact Denial before ordinary negative-answer handling.
12. For ordinary empty NOERROR, authenticate exact-owner NODATA and then wildcard NODATA.
13. For conventional NXDOMAIN without NXNAME, authenticate signed NSEC or NSEC3 closest-encloser, next-closer, and wildcard nonexistence evidence.

Direct iterative recursion discovers delegation endpoints itself. Locally validating forwarding obtains the same classes of DNSSEC data through configured recursive forwarders with RD=1, DO enabled, and CD=1, but does not accept the forwarder's AD assertion as trust evidence. Private validating stubs use their configured authoritative namespace and an out-of-band DNSKEY anchor rather than the public root anchor.

## NSEC authenticated denial

`internal/gcdns/dnssec_nsec.go` implements the conventional unhashed authenticated-denial primitives.

Implemented source boundaries include signed exact-owner proof for intentionally unsigned delegations, exact-owner NODATA proof, canonical NSEC interval processing including wrap-around, conservative NXDOMAIN closest-encloser/next-closer/wildcard proof, authenticated-zone boundary checks, and fail-closed handling for unsigned or invalid proof material.

The conventional NXDOMAIN implementation deliberately requires explicit authenticated closest-encloser evidence. It does not infer a closest encloser merely because an ancestor has no NSEC owner. Empty Non-Terminal names can exist without owning ordinary RRsets, and DNAME or delegation state at an ancestor must not be bypassed by optimistic inference.

RFC 4470 minimally covering NSEC records remain ordinary NSEC proof material from a validator's perspective. Beacon may validate such records when they satisfy the existing authenticated interval and wildcard requirements; RFC 4470 online-signing behavior does not create a separate NXDOMAIN trust shortcut.

## NSEC3 authenticated denial

`internal/gcdns/dnssec_nsec3.go` implements the hashed denial path.

Beacon supports exact-name NSEC3 NODATA, closest-encloser/next-closer/wildcard NSEC3 NXDOMAIN proof, exact-name NSEC3 proof for intentionally unsigned delegations, and a deliberately narrow RFC 5155 Opt-Out path for proving that a referral crosses into an unsigned delegated child. Proof records must use a consistent supported SHA-1 parameter set, remain inside the authenticated zone, and validate cryptographically with authenticated DNSKEY material.

Generic terminal NODATA and NXDOMAIN validation remains non-Opt-Out. An Opt-Out NSEC3 RR does not generally prove whether every insecure delegation it covers exists or does not exist, so Beacon does not use Opt-Out to promote terminal negative responses to `DNSSECSecure`.

## Scoped NSEC3 Opt-Out

Beacon uses NSEC3 Opt-Out only for DS-absence authentication at an actual delegation boundary.

If an exact matching NSEC3 RR exists for the child delegation, Beacon accepts the normal signed bitmap proof when NS is present, DS is absent, and SOA is absent. The exact matching record may carry the Opt-Out bit; its owner hash and authenticated bitmap still establish the delegation itself.

If the insecure delegation was omitted from the NSEC3 chain, Beacon requires all of the following before returning `DNSSECInsecure`:

- the DNS referral contains an actual referral NS RRset at the child zone, because Opt-Out coverage alone does not assert that the delegation exists;
- authenticated NSEC3 material establishes the closest provable encloser inside the secure parent zone;
- Beacon derives the delegation's next-closer name from that closest encloser;
- an authenticated NSEC3 RR covers that next-closer name;
- the covering NSEC3 RR has the Opt-Out bit set;
- every NSEC3 RRset relied upon by the proof validates with the authenticated parent-zone DNSKEY set; and
- no DS RR for the delegated child is present in the response.

A missing referral NS RRset leaves the delegation `DNSSECIndeterminate`. A covering NSEC3 RR without the required Opt-Out bit is rejected. Unknown NSEC3 flag bits are rejected. This scoped transition never restores secure trust below the resulting insecure branch without a separate configured trust anchor.

## RFC 9824 Compact Denial of Existence

RFC 9824 defines Compact Denial of Existence as a signed NODATA-style response for a nonexistent name. It is distinct from conventional NXDOMAIN proof and from RFC 4470 minimally covering NSEC.

`internal/gcdns/dnssec_compact_denial.go` recognizes the authenticated NXNAME Meta-TYPE signal before ordinary NODATA or conventional NXDOMAIN validation.

A Compact Answer is accepted only when the proof itself establishes the RFC 9824 shape:

- the Answer section is empty;
- an NSEC proof has an owner matching QNAME and a Type Bit Maps field containing exactly RRSIG, NSEC, and NXNAME;
- an NSEC3 proof matches the QNAME hash and contains exactly NXNAME in its Type Bit Maps field;
- the relied-on NSEC or NSEC3 RRset validates cryptographically with authenticated zone DNSKEY material;
- NSEC3 proof remains non-Opt-Out and subject to existing authenticated-zone and supported-hash checks;
- malformed NXNAME material is bogus and cannot fall through into ordinary NODATA handling;
- ordinary NODATA and Empty Non-Terminal responses without NXNAME remain distinct and use the existing NODATA path; and
- an explicit query for the NXNAME Meta-TYPE is answered locally with FORMERR and is not sent into normal resolution.

Normal Compact Answers use NOERROR. When the upstream response has the RFC 9824 Compact Answers OK response flag, a Compact Answer using NXDOMAIN is also accepted. NXNAME with NXDOMAIN but without the CO response flag fails closed instead of being treated as conventional NXDOMAIN.

## RFC 9824 Compact Answers OK hop-by-hop handling

EDNS Compact Answers OK is hop-by-hop. Beacon does not copy a downstream client's CO bit directly into upstream traffic. Instead, `Request.CompactAnswersOK` records whether the resolver component itself is prepared to consume Compact Answers.

The validating iterative resolver, `ValidatingForwardingResolver`, and the private validating stub enable that internal capability for validation work when appropriate. Plain non-validating resolver paths do not automatically inherit a downstream client's CO bit.

After DNSSEC validation establishes a Compact Denial result, Beacon records `Result.CompactDenial` and `Result.CompactDenialCO`. These fields survive defensive cache cloning. The cached semantic result is not rewritten for the client that caused the cache insertion.

`prepareCompactDenialForClient` performs downstream response presentation after policy/authority/cache/resolver processing:

- a DNSSEC-capable downstream request with DO set and CO clear receives NOERROR with the authenticated NXNAME proof, DO set, and response CO clear;
- a DNSSEC-capable downstream request with both DO and CO set receives NXDOMAIN with the authenticated NXNAME proof and response CO set;
- a downstream request without DO receives NXDOMAIN with Compact-Denial NSEC/NSEC3/RRSIG proof removed and response CO clear;
- if the downstream request did not contain EDNS, Beacon does not emit an unsolicited OPT record; and
- cached Compact Denial metadata remains unchanged while the returned DNS message is a defensive copy.

## Signed CNAME and DNAME chains

`internal/gcdns/alias.go`, `internal/gcdns/iterative.go`, and `internal/gcdns/iterative_dnssec.go` implement the bounded alias-chain execution path used by Internet recursion. Routed resolver composition and locally validating forwarding use the same shared alias parsing and trust-state combination.

Ordinary CNAME data is a normal signed RRset. In a secure zone, a CNAME link must validate with an authenticated RRSIG before the validating resolver may follow it.

DNAME follows RFC 6672. Beacon selects the closest applicable DNAME only for names strictly below its owner, performs deterministic suffix substitution, enforces the DNS name-length limit, and accepts an accompanying synthesized CNAME only when its target is exactly the DNAME-derived target and its TTL is either zero or equal to the DNAME TTL. The synthesized CNAME itself must be unsigned. DNSSEC trust comes from the signed DNAME RRset.

Alias processing is bounded to 16 transitions and rejects CNAME/DNAME cycles, conflicting DNAME data, multiple CNAME records at one owner, mismatched DNAME synthesis, and malformed alias state. A zero-TTL synthesized CNAME prevents the merged result from becoming cacheable as a fresh combined chain.

For validating iterative resolution, every externally chased target begins a new root-to-target trust walk. For `ValidatingForwardingResolver`, a recursive forwarder may return the source alias plus target-zone data in one response, but Beacon isolates and validates the current alias link and issues a fresh locally validated forwarded query for the target. For routed private validation, the route is selected again for the target name so a target outside an anchored private namespace does not inherit that namespace's trust anchor.

The combined chain is only `DNSSECSecure` when all hops are secure. An insecure hop makes the completed chain insecure, while a bogus or indeterminate hop fails closed rather than being hidden by another hop.

RFC 6672 also requires validators to understand DNAME when authenticating negative answers. After an NSEC or NSEC3 NXDOMAIN proof validates securely, Beacon rejects the response if the authenticated closest-encloser bitmap states that an applicable DNAME exists and substitution should have occurred.

## DNSSEC-aware out-of-bailiwick authoritative nameserver discovery

`internal/gcdns/referral_discovery.go` resolves authoritative NS hostnames that are outside the delegated child without trusting their Additional-section addresses.

Beacon accepts direct A/AAAA glue only for an advertised NS hostname inside the delegated child. If an in-domain NS lacks valid glue, that condition is retained as a mandatory-glue failure boundary instead of recursively resolving the same name and creating a circular dependency. Sibling and unrelated NS hostnames are classified for ordinary recursive address discovery; their Additional A/AAAA records are ignored.

External NS A and AAAA lookup runs through the same resolver mode as the original query. Plain Internet resolution uses the plain iterative resolver. DNSSEC-validating Internet resolution uses the validating resolver. Private validating stub resolution permits sibling nameserver discovery only when the hostname remains inside the configured private stub namespace and resolves it through the same validating private path.

The nameserver discovery state is request-scoped. It caches successful NS endpoints only for the current top-level resolution, rejects active hostname-discovery cycles, and allows no more than 32 distinct external NS hostname discoveries per top-level request. A failure resolving one external NS hostname does not stop another advertised external NS from being tried.

Only syntactically valid IPv4 A and 128-bit IPv6 AAAA records become port-53 targets. Alias processing remains active for an NS hostname address lookup, but only A/AAAA data at the terminal alias owner is accepted. Resolved targets are deduplicated and sorted before entering the normal scheduler.

A discovered server address does not authenticate child-zone data. DS/DNSKEY and terminal RRset validation still decides the DNSSEC result obtained from that server.

The detailed Internet-discovery design and current limits are in `docs/out-of-bailiwick-nameserver-discovery.md`. Private validating-stub constraints are in `docs/private-stub-dnssec.md`.

## RFC 9156 QNAME minimisation

`internal/gcdns/qname_minimisation.go`, `internal/gcdns/iterative.go`, and `internal/gcdns/iterative_dnssec.go` implement Beacon's privacy-preserving QNAME minimisation path for direct iterative recursion.

For eligible Internet data queries, Beacon sends a fixed A minimisation QTYPE regardless of the client's original QTYPE and reveals one additional QNAME label at a time from the current known authority boundary. Referrals advance that boundary. NOERROR non-referral responses, including NODATA and CNAME, advance the minimisation cursor without becoming the client's final answer. DNAME and compatibility failures return control to the full-QNAME path.

A request-scoped counter limits minimisation to 10 probes for the complete top-level resolution. Alias-target resolution and external authoritative nameserver discovery share the same `resolutionState`, so related sub-resolution work does not receive an independent amplification budget. Budget exhaustion falls back to the normal original-QNAME/original-QTYPE iterative query.

Beacon does not yet implement RFC 8020 NXDOMAIN cuts. Parent-side DS and selected meta/transfer QTYPEs remain outside the current minimisation stage.

On a secure branch, a non-referral minimisation response must authenticate using the currently trusted DNSKEY set before it may influence the minimisation cursor. If the result is `DNSSECIndeterminate`, Beacon abandons minimisation and sends the full original query rather than using unproven information for zone-cut inference.

The complete source boundary is described in `docs/qname-minimisation.md`.

## Wildcard-expanded positive answers

`internal/gcdns/dnssec_wildcard.go` closes the positive-answer wildcard validation gap identified by RFC 4035 and RFC 5155.

A positive RRset is first cryptographically verified. If a valid signature has a `RRSIG Labels` value equal to the RRset owner-label count, Beacon accepts it as an ordinary directly signed RRset without a wildcard denial proof. A literal wildcard owner such as `*.example.test.` remains an exact-owner response even though DNSSEC excludes the leading wildcard label from its RRSIG Labels count. If a validated signature on a non-wildcard owner has fewer labels, Beacon derives the immediate ancestor of the generating wildcard and the corresponding next-closer name.

For NSEC responses, Beacon requires a signed NSEC interval covering the next-closer name. For NSEC3 responses, Beacon requires a signed non-Opt-Out NSEC3 RR covering the next-closer hash. An authenticated exact/matching denial record for the next-closer proves a closer name exists and makes the wildcard expansion bogus.

A cryptographically valid wildcard-expanded answer without the required no-closer-match proof fails closed and is not classified `DNSSECSecure`.

## Wildcard NODATA

Empty NOERROR responses can also result from a wildcard matching QNAME while the wildcard owner lacks QTYPE. Beacon validates these responses explicitly instead of treating them as ordinary exact-owner NODATA.

For NSEC, Beacon selects the closest wildcard-owner NSEC applicable to QNAME, authenticates its RRset, requires its bitmap to omit both QTYPE and CNAME, derives the next-closer name from the wildcard's immediate ancestor, and requires authenticated no-closer-match proof.

For NSEC3, Beacon requires an authenticated closest-encloser proof, authenticated non-Opt-Out NSEC3 coverage of the next-closer name, and an authenticated NSEC3 RR matching the corresponding wildcard owner. The wildcard NSEC3 bitmap must omit QTYPE and CNAME.

## Routed forward/stub DNSSEC boundary

`internal/gcdns/routing.go` can select direct recursion, recursive forwarding, or a non-recursive stub after the normal policy/authority/cache stages. Route selection itself is not trust evidence.

Raw `ForwardingResolver`, terminal-only `StubResolver`, and ordinary `DelegatingStubResolver` clear AD and return `DNSSECIndeterminate`.

`ValidatingForwardingResolver` provides local root-anchored validation for ordinary Internet forwarding. It uses configured recursive forwarders only as data transports, sends validation traffic with RD=1/DO/CD, clears upstream AD, authenticates the root DNSKEY RRset against Beacon's root DS anchors, and validates DS-to-DNSKEY transitions to the response signer zone.

Signed forwarded response fragments must resolve to one RRSIG signer zone. Beacon walks trust to that signer zone instead of probing DS at every ordinary owner. When a name between the current authenticated zone and a deeper signer zone is not a delegation, `AuthenticateNonDelegationDS` requires authenticated exact-name NSEC or non-Opt-Out NSEC3 DS-NODATA proof before the current parent keyset may continue. More compact Empty Non-Terminal proof forms are deliberately not inferred yet.

If authenticated denial proves a real delegation has no DS, the validating forwarder transitions to `DNSSECInsecure`. A missing DS alone is insufficient, and a deeper DS does not restore trust below that boundary. An unclassifiable DS state fails closed.

DS client queries preserve parent-side semantics: the terminal DS RRset is validated by authenticated parent keys. Recursive CNAME/DNAME responses are split into separately validated hops; target data returned alongside a source alias is not trusted under source-zone keys.

`PrivateTrustAnchorResolver` provides local terminal validation for a configured private signed zone from an out-of-band DNSKEY anchor. `ValidatingDelegatingStubResolver` extends that private apex trust through signed child DS/DNSKEY transitions or authenticated insecure-child transitions while preserving stub namespace and referral restrictions.

The routed policies are documented in `docs/resolver-routing.md`, `docs/validating-forwarding.md`, `docs/routed-dnssec-policy.md`, and `docs/private-stub-dnssec.md`.

## Corrected development history

An intermediate branch-only experiment attempted to broaden NSEC NXDOMAIN handling by inferring nonexistent ancestors and using the authenticated DNSKEY zone apex as an implicit closest encloser. Review against RFC 4592, RFC 6672, and RFC 9824 showed that this was not a safe general validator rule: Empty Non-Terminals complicate existence inference, and an implicit apex proof cannot establish that DNAME does not apply. That experiment, its tests, and its unfinished source gate were removed before being added to CI or represented as accepted functionality. Branch history remains intact; no force rewrite was used.

## Deliberate boundary

DNSSEC algorithm/key-size policy, authenticated trust-anchor persistence/rollover, RFC 8020 NXDOMAIN-cut integration, parent-side DS minimisation for direct recursion, authenticated forwarding-state reuse/cache lifecycle, broader standards-backed forwarding non-delegation/Empty Non-Terminal proof forms, authenticated upstream transport policy, parallel/persistent nameserver infrastructure discovery, encrypted forwarding, and end-to-end runtime acceptance remain staged work.

Locally validating forwarding currently re-establishes the needed trust chain per resolution. This is deliberate correctness-first behavior until reusable authenticated state has an explicit expiration, rollover, cache-isolation, and invalidation model.

## Production status

This code remains isolated from production DNS traffic. Existing production AdGuard Home and Unbound behavior is unchanged. Production cutover requires remaining DNSSEC work, broader resolver parity, executable testing, migration and rollback procedures, and GoreeCloud production-readiness acceptance.

## Next DNSSEC stages

- Add algorithm, digest, and key-size policy with explicit unsupported-algorithm behavior.
- Add trust-anchor lifecycle, secure private-anchor provisioning/storage policy, authenticated state persistence, and rollover automation.
- Broaden locally validating forwarding only where additional standards-backed non-delegation and Empty Non-Terminal denial forms can be authenticated safely.
- Add end-to-end runtime acceptance against controlled signed, unsigned, bogus, wildcard, CNAME, DNAME, out-of-bailiwick-NS, QNAME-minimisation, raw-forward, validating-forward, parent-side-DS, non-delegation-label, private-anchor, signed-private-child, insecure-private-child, stub, split-horizon, NSEC, NSEC3, Opt-Out, NXNAME, CO, and denial-of-existence test zones.
