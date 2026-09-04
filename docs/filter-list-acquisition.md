# Beacon Bounded Signed Filter-List Acquisition

Beacon now has a bounded remote-acquisition layer for signed filter-list snapshots. It is intentionally narrow and fail closed.

`PolicyFilterListAcquirer` retrieves only three artifacts:

1. configured metadata URI;
2. configured detached-signature URI; and
3. the content URI carried inside successfully authenticated metadata.

The metadata and signature bootstrap URIs must be absolute credential-free HTTPS URLs, must use an explicitly allowlisted host, and must share the same HTTPS authority. Redirects are disabled by the default client. Non-200 responses fail. Metadata, signature, and content reads are byte-bounded.

Beacon authenticates the exact metadata bytes with an explicitly configured local Ed25519 trusted-key store before it fetches list content. An unauthenticated metadata document therefore cannot redirect Beacon to an arbitrary content location. After authentication, the signed `source_uri` must independently pass the HTTPS and host-allowlist policy before content is retrieved.

The local trusted-key state is now durably represented by `PolicyFilterListTrustedKeyStore`. Key IDs are stable administrative identities, public keys are fingerprint-bound, duplicate key IDs and duplicate public keys are rejected, and persistence uses a protected temporary file followed by replacement of the configured state path. Rotation is explicit: a distinct reviewed key is added under a new key ID, both identities may remain active during transition, and the old identity is then persistently revoked. Revoked key records are retained for audit/recovery but are excluded from the `PolicyFilterListTrustedKeys` map used by signature verification. Reusing a revoked key ID or aliasing the same public key under another ID is rejected. Revoking the last active key is permitted as an emergency fail-closed action; subsequent signed-list verification then fails until a distinct trusted key is deliberately added.

Trusted-key state loading is strict: unknown JSON fields, trailing JSON data, invalid Ed25519 encodings, fingerprint mismatches, duplicate identities/fingerprints, malformed lifecycle timestamps, and incomplete revocation records are rejected. Beacon still does not discover or trust signing keys from metadata, DNS, redirects, remote content, or the acquired list itself.

The downloaded content is then verified against the signed content SHA-256 and passed through the existing snapshot validation and lifecycle rules for source continuity, monotonic sequence, freshness/expiry, bounded history, and rollback.

This layer still does not provide scheduled refresh, retry/backoff policy, offline grace behavior, transport pinning, Everkeep-backed trusted-key/filter lifecycle recovery, multi-list composition, managed enable/disable administration, or production activation. Those remain separate acceptance work.

AdGuard Home and Unbound remain production-authoritative. This acquisition and trusted-key lifecycle code does not change production DNS listeners, filtering state, client assignment, recursion/forwarding paths, or cutover authority.