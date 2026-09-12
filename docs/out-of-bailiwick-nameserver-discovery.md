# Beacon Out-of-Bailiwick Nameserver Discovery

Beacon Resolver follows DNS referrals without trusting arbitrary Additional-section address data.

## Referral classification

`internal/gcdns/referral_discovery.go` separates referral nameserver names into three groups:

1. nameservers below or equal to the delegated child zone that have valid A/AAAA glue in Additional;
2. nameservers below or equal to the delegated child zone that are missing mandatory in-domain glue;
3. sibling or unrelated nameserver names that are outside the delegated child zone and therefore require ordinary recursive address discovery.

Only A/AAAA records for an advertised in-domain nameserver are accepted directly as glue. Additional-section addresses for sibling or unrelated nameservers are ignored even when the owner matches an advertised NS hostname. Beacon resolves those names through normal recursion instead of promoting unauthenticated Additional data into a resolver target.

This is deliberately conservative. RFC 1034 requires glue to break the circular dependency for nameservers inside the delegated zone, while RFC 9471 clarifies that authoritative referral responses must include all available in-domain glue and set TC when message size prevents that complete glue from fitting.

## External nameserver address discovery

For an out-of-bailiwick nameserver, Beacon performs bounded A and AAAA resolution through the same resolver mode that is processing the original query. Plain iterative resolution uses the plain iterative path. DNSSEC-validating resolution uses the validating path, so signed nameserver-address data can retain its DNSSEC protection and insecure address zones are handled through the existing authenticated secure-to-insecure boundary.

Alias processing remains active during nameserver-address lookup. If the nameserver hostname is a CNAME or DNAME result, Beacon follows the existing bounded alias rules and accepts only A/AAAA data at the terminal alias owner.

Successfully resolved addresses are retained only in the current resolution state. This initial implementation does not create a new persistent or cross-request nameserver-address cache.

## Work and cycle bounds

A request-scoped resolution state records active nameserver hostname lookups and successful address results.

- At most 32 distinct external nameserver hostnames may enter address discovery during one top-level resolution.
- Re-entering a nameserver hostname while that hostname is already being resolved is rejected as a nameserver-address discovery cycle.
- Successful address lookup is reused inside the same top-level resolution.
- A failed external nameserver hostname does not prevent another advertised external nameserver from being tried.
- If no usable external address exists and mandatory in-domain glue is missing, resolution fails closed rather than recursively chasing the in-domain nameserver and creating a glue dependency loop.

These limits follow RFC 1034's resolver-design requirement to bound packets and auxiliary resolver work even when DNS data is misconfigured or malicious.

## Address validation

Beacon accepts only syntactically valid IPv4 A data or 128-bit IPv6 AAAA data when converting DNS records into port-53 resolver endpoints. Malformed address byte strings are ignored.

The resulting target list is deduplicated and sorted before it enters the existing TargetScheduler. The scheduler therefore retains its normal timeout, cancellation, failover, concurrency, and target-health behavior after address discovery completes.

## DNSSEC boundary

The validating resolver authenticates the referral's secure/insecure delegation state before proceeding below the child. Out-of-bailiwick address discovery does not grant DNSSEC trust to the child zone and does not allow a previous zone's DNSKEY set to authenticate unrelated nameserver-host data.

A discovered address only identifies a server to contact. The existing DS/DNSKEY chain and terminal RRset validation remain responsible for deciding whether data obtained through that server is Secure, Insecure, Indeterminate, or Bogus.

## Deliberate limits

This source milestone resolves external nameserver hostnames sequentially within a bounded request state. Parallel auxiliary address discovery, persistent nameserver infrastructure caching, lame-server scoring across requests, and QNAME minimization remain separate resolver work.

Production DNS remains unchanged. `internal/gcdns` is still isolated from the inherited AdGuard Home and Unbound request path pending executable validation, migration/rollback proof, and explicit production acceptance.
