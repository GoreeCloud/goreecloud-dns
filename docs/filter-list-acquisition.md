# Beacon Bounded Signed Filter-List Acquisition

Beacon now has a bounded remote-acquisition layer for signed filter-list snapshots. It is intentionally narrow and fail closed.

`PolicyFilterListAcquirer` retrieves only three artifacts:

1. configured metadata URI;
2. configured detached-signature URI; and
3. the content URI carried inside successfully authenticated metadata.

The metadata and signature bootstrap URIs must be absolute credential-free HTTPS URLs, must use an explicitly allowlisted host, and must share the same HTTPS authority. Redirects are disabled by the default client. Non-200 responses fail. Metadata, signature, and content reads are byte-bounded.

Beacon authenticates the exact metadata bytes with an explicitly configured local Ed25519 trusted-key store before it fetches list content. An unauthenticated metadata document therefore cannot redirect Beacon to an arbitrary content location. After authentication, the signed `source_uri` must independently pass the HTTPS and host-allowlist policy before content is retrieved.

The downloaded content is then verified against the signed content SHA-256 and passed through the existing snapshot validation and lifecycle rules for source continuity, monotonic sequence, freshness/expiry, bounded history, and rollback.

This layer does not discover signing keys from the network, DNS, redirects, metadata, or list contents. It does not provide signing-key rotation/revocation, persistent trusted-key storage, scheduled refresh, retry/backoff policy, offline grace behavior, transport pinning, Everkeep-backed lifecycle recovery, or production activation. Those remain separate acceptance work.

AdGuard Home and Unbound remain production-authoritative. This acquisition code does not change production DNS listeners, filtering state, client assignment, recursion/forwarding paths, or cutover authority.
