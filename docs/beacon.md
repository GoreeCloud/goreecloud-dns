# GoreeCloud Beacon

GoreeCloud Beacon is the official feature umbrella for the first-party capabilities of GoreeCloud DNS.

GoreeCloud DNS remains the application and service name. Beacon is not a separate daemon, product, or deployment boundary.

## Native resolver transition

The first executable Beacon foundation lives in `internal/gcdns` and is intentionally isolated from the inherited AdGuard Home production request path.

The native pipeline is:

`Policy -> Authoritative DNS -> Cache -> Resolver`

The contracts are designed so first-party caching, recursive resolution, forwarding, authoritative DNS, DNSSEC validation, filtering, observability, encrypted DNS, DHCP, clustering, and administration can be introduced incrementally without recreating a permanent AdGuard Home/Unbound split.

## Security boundary

The native foundation currently enforces source-level invariants for:

- DNSSEC validation enabled;
- DNS rebinding protection enabled;
- explicit recursion ACLs;
- no unrestricted recursion unless public recursion is explicitly enabled;
- no unrestricted administrative ACL;
- DNSSEC `bogus` results rejected before cache insertion.

These checks are development controls, not production acceptance evidence.

## Production boundary

No production traffic is routed through `internal/gcdns` yet. Existing AdGuard Home and Unbound runtime behavior remains unchanged until the native path has executable parity, tests, security validation, migration procedures, rollback procedures, and explicit production acceptance.

## Next implementation sequence

1. Native sharded DNS cache with TTL aging, negative caching, serve-stale, statistics, and bounded capacity.
2. Resolver target scheduler with cancellation, timeout, failover, and latency-aware selection.
3. UDP/TCP transport with truncation fallback and defensive response validation.
4. Iterative recursion and delegation walking.
5. DNSSEC trust-anchor, DS/DNSKEY, RRSIG, and authenticated-denial validation.
6. Forward, conditional, stub, and split-horizon routing.
7. Encrypted DNS, authoritative DNS, filtering, DHCP, clustering, APIs, and administration.
8. Controlled production integration and replacement acceptance.
