---
title: "Beacon Bounded Signed Filter-List Acquisition"
document_type: "Development Capability Record"
version: "v0.6"
status: "Draft"
classification: "Internal"
last_updated: "2026-09-15"
---

# Beacon Bounded Signed Filter-List Acquisition

Beacon now has a bounded remote-acquisition layer for signed filter-list snapshots. It is intentionally narrow and fail closed.

`PolicyFilterListAcquirer` retrieves only three artifacts:

1. configured metadata URI;
2. configured detached-signature URI; and
3. the content URI carried inside successfully authenticated metadata.

The metadata and signature bootstrap URIs must be absolute credential-free HTTPS URLs, must use an explicitly allowlisted host, and must share the same HTTPS authority. Redirects are rejected by the acquisition boundary for both the default HTTP client and caller-supplied clients. When a caller supplies a client, Beacon clones its client configuration and overrides only redirect handling, so custom transport and timeout settings can be retained without allowing the caller to weaken the no-redirect policy or mutating the caller's shared client. Non-200 responses fail. Metadata, signature, and content reads are byte-bounded.

Beacon authenticates the exact metadata bytes with an explicitly configured local Ed25519 trusted-key store before it fetches list content. An unauthenticated metadata document therefore cannot redirect Beacon to an arbitrary content location. After authentication, the signed `source_uri` must independently pass the HTTPS and host-allowlist policy before content is retrieved.

The local trusted-key state is now durably represented by `PolicyFilterListTrustedKeyStore`. Key IDs are stable administrative identities, public keys are fingerprint-bound, duplicate key IDs and duplicate public keys are rejected, and persistence uses a protected temporary file followed by replacement of the configured state path. Rotation is explicit: a distinct reviewed key is added under a new key ID, both identities may remain active during transition, and the old identity is then persistently revoked. Revoked key records are retained for audit/recovery but are excluded from the `PolicyFilterListTrustedKeys` map used by signature verification. Reusing a revoked key ID or aliasing the same public key under another ID is rejected. Revoking the last active key is permitted as an emergency fail-closed action; subsequent signed-list verification then fails until a distinct trusted key is deliberately added.

Trusted-key state loading is strict: unknown JSON fields, trailing JSON data, invalid Ed25519 encodings, fingerprint mismatches, duplicate identities/fingerprints, malformed lifecycle timestamps, and incomplete revocation records are rejected. Beacon still does not discover or trust signing keys from metadata, DNS, redirects, remote content, or the acquired list itself.

The downloaded content is then verified against the signed content SHA-256 and passed through the existing snapshot validation and lifecycle rules for source continuity, monotonic sequence, freshness/expiry, bounded history, and rollback.

## Development refresh and managed-list orchestration

Development code also includes `PolicyFilterListRefreshController`. It provides a caller-driven refresh orchestration boundary with a positive refresh interval, capped exponential retry/backoff, one-refresh-at-a-time enforcement, privacy-safe status, and an explicit offline-grace usability window for a previously authenticated active snapshot. The controller deliberately owns no goroutine and no production listener; callers decide when to invoke `Refresh` and may use `NextAttempt` to integrate with a later runtime scheduler. Offline grace never relaxes signature, digest, source-identity, sequence, or acquisition validation.

`PolicyFilterListManager` provides deterministic composition of independently authenticated managed sources into ordinary Beacon policy rules. It binds local managed-list identities to expected remote source identities, distinguishes required and optional sources, prevents required sources from being disabled, permits explicit administrative enablement changes for optional sources, fails closed when a required source is unavailable or a source identity mismatches, and emits privacy-minimized managed-source state. It owns no acquisition goroutine, listener, or production activation path.

Recovery work in this Development stack includes strict candidate staging, integrity-bound recovery generations, and bounded recovery-artifact import/validation. These recovery candidates are not self-authorizing and do not establish Everkeep runtime acceptance or automatic restore activation.

## Remaining acceptance boundaries

The Development components above do **not** establish a production scheduler, production list activation, transport pinning, Everkeep-backed durable runtime integration, target-environment acceptance, production cutover, Release Candidate eligibility, or Stable status. Those remain separate evidence-gated work. Additional managed-list lifecycle capabilities defined by the authoritative GoreeCloud DNS specification remain subject to their own implementation and acceptance evidence.

AdGuard Home and Unbound remain production-authoritative. This acquisition, refresh, managed-list, trusted-key, and recovery-candidate Development code does not change production DNS listeners, filtering state, client assignment, recursion/forwarding paths, or cutover authority.
