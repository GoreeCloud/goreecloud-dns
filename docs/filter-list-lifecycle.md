# Beacon Filter-List Lifecycle Foundation

The native Beacon filter-list lifecycle manages already-acquired immutable list snapshots. It is intentionally separate from remote acquisition.

A candidate snapshot carries a stable source ID, credential-free absolute HTTPS source URI, publisher identity, monotonically increasing sequence, issued/expiry timestamps, reviewed metadata SHA-256, content SHA-256, and bounded content bytes.

Activation fails closed when the source identity changes unexpectedly, sequence does not increase, active content is reused, freshness is invalid, the candidate is expired/not-yet-valid, a digest is malformed, content does not match its digest, or the content exceeds the configured list bound.

The previous active snapshot is retained in a bounded rollback history. Rollback selects an exact retained content SHA-256 and revalidates the snapshot at rollback time, including expiry. Missing or expired rollback state fails rather than being reconstructed from a mutable remote URL.

This foundation deliberately performs no network I/O. `MetadataSHA256` is an immutable metadata identity only and must not be interpreted as proof of a digital signature. Authenticated acquisition, signature verification, source-key trust, update scheduling, persistent state, Everkeep-backed recovery, multi-list conflict policy, and production activation remain future acceptance work.
