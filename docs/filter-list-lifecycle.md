# Beacon Filter-List Lifecycle Foundation

The native Beacon filter-list lifecycle manages immutable list snapshots and keeps activation separate from network acquisition.

A candidate snapshot carries a stable source ID, credential-free absolute HTTPS source URI, publisher identity, monotonically increasing sequence, issued/expiry timestamps, exact metadata SHA-256, content SHA-256, and bounded content bytes.

Activation fails closed when the source identity changes unexpectedly, sequence does not increase, active content is reused, freshness is invalid, the candidate is expired/not-yet-valid, a digest is malformed, content does not match its digest, or the content exceeds the configured list bound.

The previous active snapshot is retained in a bounded rollback history. Rollback selects an exact retained content SHA-256 and revalidates the snapshot at rollback time, including expiry. Missing or expired rollback state fails rather than being reconstructed from a mutable remote URL.

## Signed metadata and source trust

`internal/gcdns/policy_filterlist_signature.go` adds the authenticated metadata boundary. Beacon accepts detached Ed25519 signatures over the exact metadata bytes only when `key_id` resolves to an explicitly configured local trusted public key. The signing key is never discovered from metadata, DNS, redirects, the list body, or another remote response.

The signed metadata schema binds the source ID, credential-free HTTPS source URI, publisher, monotonic sequence, issue/expiry window, content SHA-256, and signing-key ID. Unknown JSON fields and trailing JSON data fail closed. After signature verification, Beacon independently recomputes the list-content SHA-256 and runs the ordinary lifecycle validation before a signed candidate may be activated with `ApplySigned`.

The resulting `MetadataSHA256` is the SHA-256 of the exact authenticated metadata bytes. It is useful as immutable evidence identity but is not itself the authentication mechanism; Ed25519 verification against the configured trust store is.

## Recovery artifact portability boundary

The managed recovery path can bind trusted signing-key recovery state and managed filter-list administrative configuration into one integrity-protected recovery generation. `internal/gcdns/policy_filterlist_recovery_bundle_codec.go` adds a bounded JSON portability boundary for that bundle so an approved recovery authority can retain or transport the artifact without bypassing Beacon validation.

Recovery bundle decoding is limited to 1 MiB, rejects unknown JSON fields and trailing JSON data, revalidates the embedded trusted-key state, managed configuration, timestamps, and bundle fingerprint, and canonicalizes managed-source ordering and SHA-256 formatting before returning the artifact. Encoding likewise validates and canonicalizes before producing deterministic, newline-terminated JSON.

The artifact is not self-authorizing. Restore staging still requires the independently retained bundle fingerprint and preserves the existing trusted-key rollback, revocation, managed-revision, source-identity, required-source, and local runtime-source gates. Encoding or decoding a bundle does not write the trusted-key store, persist managed configuration, refresh a list, start a scheduler, alter resolver policy, or activate production state.

## Remaining acquisition and recovery boundary

This implementation still performs no network I/O. It does not download a source URI, follow redirects, perform TLS pinning, schedule refreshes, decide offline retry policy, infer publisher trust from HTTPS alone, or activate restored recovery state. Those behaviors require separately reviewed acquisition and recovery layers with bounded downloads, redirect/host policy, transport security, deterministic failure behavior, and explicit authorization boundaries.

Trusted signing-key rotation and revocation state now has a local persistence model and an integrity-bound recovery representation, but broader durable filter-list lifecycle state and rollback history are not yet Everkeep-backed. The recovery bundle codec does not itself connect to Everkeep or any other remote recovery service. Everkeep integration/acceptance, persistent managed-configuration activation, multi-list conflict policy, Glaze UI administration, target-environment runtime acceptance, and production activation remain separate gates.

No filter-list lifecycle, signed metadata, recovery-bundle, or recovery-artifact operation authorizes production cutover. Production AdGuard Home and Unbound behavior remains unchanged until the complete migration and rollback evidence set is accepted.
