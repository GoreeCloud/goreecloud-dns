# Beacon Iterative DNSSEC Validation

GoreeCloud DNS has a staged validating iterative resolver in `internal/gcdns/iterative_dnssec.go`.

## Current trust flow

The validating path performs these steps before a secure answer may be returned:

1. Query the root zone for DNSKEY material with DNSSEC signaling enabled.
2. Authenticate the root DNSKEY RRset against the carried GoreeCloud Beacon root DS trust anchors.
3. Resolve the original question against the currently trusted authority set.
4. For every signed referral, authenticate the child DS RRset with the currently trusted parent DNSKEY set.
5. Query the child authority for its DNSKEY RRset.
6. Authenticate that DNSKEY RRset against the authenticated child DS RRset.
7. Carry only the resulting authenticated child DNSKEY set into the next secure delegation step.
8. When DS is absent, accept an insecure child only when signed NSEC, exact-name NSEC3, or the narrowly scoped NSEC3 Opt-Out delegation proof described below authenticates the secure-to-insecure transition.
9. Once an insecure delegation is authenticated, preserve `DNSSECInsecure` below that boundary instead of attempting to recreate trust without another configured trust anchor.
10. For a positive terminal response, group the answer into RRsets and validate each RRset against matching RRSIG material using the authenticated DNSKEY set for the answering zone.
11. If a validated positive RRSIG has fewer `RRSIG Labels` than its expanded owner name, treat the RRset as wildcard synthesized and require authenticated proof that the wildcard was the correct match.
12. For an empty response carrying NXNAME, validate RFC 9824 Compact Denial before ordinary negative-answer handling.
13. For an ordinary empty NOERROR response without NXNAME, authenticate exact-owner NODATA and then wildcard NODATA.
14. For conventional NXDOMAIN without NXNAME, authenticate signed NSEC or NSEC3 closest-encloser, next-closer, and wildcard nonexistence evidence.

If a delegation cannot establish either secure DS trust or authenticated denial proving an intentionally unsigned child, the validating path stops before contacting the child authority. Positive terminal RRsets and malformed or cryptographically invalid denial proofs fail closed.

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
- every NSEC3 RRset relied upon by the proof validates with the authenticated parent-zone DNSKEY set;
- no DS RR for the delegated child is present in the response.

A missing referral NS RRset leaves the delegation `DNSSECIndeterminate`. A covering NSEC3 RR without the required Opt-Out bit is rejected. Unknown NSEC3 flag bits are rejected. This scoped transition never restores secure trust below the resulting insecure branch without a separate configured trust anchor.

This behavior follows the RFC 5155 unsigned-referral model while preserving the distinction between proving an insecure delegation transition and proving authenticated nonexistence. The same Opt-Out proof is therefore not reused for terminal NODATA and NXDOMAIN.

## RFC 9824 Compact Denial of Existence

RFC 9824, published in September 2025 and updating RFCs 4034 and 4035, defines Compact Denial of Existence as a signed NODATA-style response for a nonexistent name. It is distinct from conventional NXDOMAIN proof and from RFC 4470 minimally covering NSEC.

`internal/gcdns/dnssec_compact_denial.go` recognizes the authenticated NXNAME Meta-TYPE signal before ordinary NODATA or conventional NXDOMAIN validation.

A Compact Answer is accepted only when the proof itself establishes the RFC 9824 shape:

- the Answer section is empty;
- an NSEC proof has an owner matching QNAME and a Type Bit Maps field containing exactly RRSIG, NSEC, and NXNAME;
- an NSEC3 proof matches the QNAME hash and contains exactly NXNAME in its Type Bit Maps field;
- the relied-on NSEC or NSEC3 RRset validates cryptographically with authenticated zone DNSKEY material;
- NSEC3 proof remains non-Opt-Out and subject to existing authenticated-zone and supported-hash checks;
- malformed NXNAME material is bogus and cannot fall through into ordinary NODATA handling;
- ordinary NODATA and Empty Non-Terminal responses without NXNAME remain distinct and use the existing NODATA path;
- an explicit query for the NXNAME Meta-TYPE is answered locally with FORMERR and is not sent into iterative resolution.

Normal Compact Answers use NOERROR. When the upstream response has the RFC 9824 Compact Answers OK response flag, a Compact Answer using NXDOMAIN is also accepted. NXNAME with NXDOMAIN but without the CO response flag fails closed instead of being treated as conventional NXDOMAIN.

## RFC 9824 Compact Answers OK hop-by-hop handling

EDNS Compact Answers OK is hop-by-hop. Beacon does not copy a downstream client's CO bit directly into upstream traffic. Instead, `Request.CompactAnswersOK` records whether the resolver component itself is prepared to consume Compact Answers. The DNSSEC-validating iterative resolver sets this internal capability for its authority and DNSKEY queries; the plain non-validating iterative resolver does not. `exchangeResolver` emits `OPT.SetCo()` only when that internal capability is true.

After DNSSEC validation establishes a Compact Denial result, Beacon records `Result.CompactDenial` and `Result.CompactDenialCO`. These fields survive defensive cache cloning. The cached semantic result is not rewritten for the client that caused the cache insertion.

`prepareCompactDenialForClient` performs downstream response presentation after policy/authority/cache/resolver processing:

- a DNSSEC-capable downstream request with DO set and CO clear receives NOERROR with response CO clear;
- a DNSSEC-capable downstream request with both DO and CO set receives NXDOMAIN with response CO set;
- a downstream request without DO receives NXDOMAIN restoration and no response CO unless the downstream query itself advertised CO;
- cached Compact Denial metadata remains unchanged while the returned DNS message is a defensive copy.

This preserves RFC 9824's hop-by-hop distinction and prevents one downstream request's EDNS flags from changing the cached result seen by another client.

## Wildcard-expanded positive answers

`internal/gcdns/dnssec_wildcard.go` closes the positive-answer wildcard validation gap identified by RFC 4035 and RFC 5155.

A positive RRset is first cryptographically verified. If a valid signature has a `RRSIG Labels` value equal to the RRset owner-label count, Beacon accepts it as an ordinary directly signed RRset without a wildcard denial proof. A literal wildcard owner such as `*.example.test.` remains an exact-owner response even though DNSSEC excludes the leading wildcard label from its RRSIG Labels count. If a validated signature on a non-wildcard owner has fewer labels, Beacon derives the immediate ancestor of the generating wildcard and the corresponding next-closer name.

For NSEC responses, Beacon requires a signed NSEC interval covering the next-closer name. An authenticated exact-owner NSEC at that name instead proves that a closer name exists and makes the wildcard expansion bogus.

For NSEC3 responses, Beacon requires a signed non-Opt-Out NSEC3 RR covering the next-closer hash. A matching authenticated NSEC3 RR instead proves that the closer name exists and makes the expansion bogus. Opt-Out proof is not reused for this positive-answer security conclusion.

A cryptographically valid wildcard-expanded answer without the required no-closer-match proof fails closed and is not classified `DNSSECSecure`.

## Wildcard NODATA

Empty NOERROR responses can also result from a wildcard matching QNAME while the wildcard owner lacks QTYPE. Beacon validates these responses explicitly instead of treating them as ordinary exact-owner NODATA.

For NSEC, Beacon selects the closest wildcard-owner NSEC applicable to QNAME, authenticates its RRset, requires its bitmap to omit both QTYPE and CNAME, derives the next-closer name from the wildcard's immediate ancestor, and then requires the same signed no-closer-match NSEC proof used by wildcard-positive validation.

For NSEC3, Beacon requires an authenticated closest-encloser proof, authenticated non-Opt-Out NSEC3 coverage of the next-closer name, and an authenticated NSEC3 RR matching the corresponding wildcard owner. The wildcard NSEC3 bitmap must omit both QTYPE and CNAME.

## Corrected development history

An intermediate branch-only experiment attempted to broaden NSEC NXDOMAIN handling by inferring nonexistent ancestors and using the authenticated DNSKEY zone apex as an implicit closest encloser. Review against RFC 4592, RFC 6672, and RFC 9824 showed that this was not a safe general validator rule: Empty Non-Terminals complicate existence inference, and an implicit apex proof cannot establish that DNAME does not apply. That experiment, its tests, and its unfinished source gate were removed before being added to CI or represented as accepted functionality. Branch history remains intact; no force rewrite was used.

## Deliberate boundary

Complete signed CNAME/DNAME chain resolution across additional authority transitions, DNSSEC algorithm/key-size policy, authenticated trust-anchor persistence/rollover, and end-to-end runtime acceptance remain staged work.

## Production status

This code remains isolated from production DNS traffic. Existing production AdGuard Home and Unbound behavior is unchanged. Production cutover requires remaining DNSSEC work, broader resolver parity, executable testing, migration and rollback procedures, and GoreeCloud production-readiness acceptance.

## Next DNSSEC stages

- Complete signed CNAME/DNAME chain validation across zone transitions.
- Add algorithm and digest policy with explicit unsupported-algorithm behavior.
- Add trust-anchor lifecycle and rollover automation.
- Add end-to-end runtime acceptance against controlled signed, unsigned, bogus, wildcard, NSEC, NSEC3, Opt-Out, NXNAME, CO, and denial-of-existence test zones.
