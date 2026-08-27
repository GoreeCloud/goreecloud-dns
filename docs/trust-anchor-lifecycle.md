# Beacon Trust-Anchor Lifecycle

This document defines the current source-level lifecycle boundary for persistent DNSSEC root trust-anchor state in GoreeCloud Beacon.

## Purpose

The built-in `RootTrustAnchors()` set is a bootstrap source, not a permanent lifecycle mechanism. Beacon needs durable, recoverable trust-anchor state so a future production resolver can survive restarts, preserve approved rollover state, reject tampering, and avoid silently changing its DNSSEC trust basis because a network source or dependency changed.

The current lifecycle implementation lives in `internal/gcdns/trust_anchor_state.go` and `internal/gcdns/trust_anchor_rollover.go`. It remains isolated from production DNS traffic and does not yet implement unattended RFC 5011 network-driven rollover.

## Persistent trust-anchor state

The persisted schema is `goreecloud-beacon-trust-anchor-state/v1`.

State contains:

- the active root DS trust-anchor set;
- the last state-update timestamp;
- at most one pending proposed replacement set;
- the pending proposal source;
- a deterministic SHA-256 fingerprint of the complete proposed set; and
- the proposal timestamp.

Only root (`.`) DS anchors are supported by this lifecycle store. Private DNSKEY trust anchors remain a separate explicitly configured routing capability and are not mixed into the root trust-anchor lifecycle file.

## Bootstrap

`BootstrapTrustAnchorState` converts the current built-in root DS bootstrap set into the persisted lifecycle schema. This creates a controlled initial state without treating later source-code changes as automatic trust-anchor activation.

## Persistent storage

`TrustAnchorStore.Save` writes versioned JSON through an owner-only temporary file, syncs the temporary file, atomically replaces the destination, and enforces mode `0600` on the resulting state file. The parent directory is created with owner-only permissions when needed.

`TrustAnchorStore.Load` rejects malformed JSON, unsupported schema versions, invalid timestamps, empty anchor sets, non-root names, duplicate records, unaccepted DS algorithms, unsupported DS digest types, malformed hexadecimal digests, and pending-update fingerprint mismatches.

The state file is runtime security state. It must not be committed to the repository and must be included in future GoreeCloud backup, restore, recovery, permission, and Everkeep acceptance work before production use.

## Update staging

`StageUpdate` does not replace the active trust set. It validates a complete candidate anchor set, requires a non-empty authenticated source description, rejects an unchanged proposal, creates a deterministic fingerprint, and records the candidate as pending.

Only one pending update may exist at a time. This prevents overlapping proposals from obscuring which exact trust basis is being reviewed.

## Explicit approval

`ApprovePending` requires the caller to provide the exact pending-set fingerprint. A mismatched or missing fingerprint is rejected. Successful approval atomically changes the in-memory lifecycle state from the prior active set to the exact reviewed pending set and clears the pending proposal.

`RejectPending` clears the proposal without changing the active set.

This is an explicit GoreeCloud approval boundary. Merely observing a new root key or downloading a new anchor file must not silently activate a new trust anchor through this source implementation.

## Restart-safe rollover timing foundation

`TrustAnchorRolloverState` introduces a separate timing-evidence schema, `goreecloud-beacon-trust-anchor-rollover/v1`, for an already authenticated candidate root trust-anchor set.

The rollover record binds:

- the deterministic fingerprint of the complete candidate set;
- the first observation time;
- the most recent observation time; and
- the hold-down deadline.

`NewTrustAnchorRolloverState` requires a positive hold-down duration and a valid root trust-anchor candidate set. `ObserveTrustAnchorCandidate` continues an existing observation window only when the complete candidate fingerprint remains unchanged. A candidate change fails closed instead of inheriting elapsed time from a different trust basis.

Persisted clock state is also fail-closed. An observation or eligibility check earlier than the persisted `last_seen_at` is rejected as a clock rollback. This prevents backwards wall-clock movement from silently satisfying or corrupting the timing boundary.

`TrustAnchorCandidateHoldDownComplete` reports timing eligibility only. A `true` result does not stage, approve, activate, save, or otherwise change the active trust-anchor set. Explicit GoreeCloud approval remains a separate mandatory boundary.

This timing model is a foundation for future RFC 5011-style lifecycle work; it is not represented as a complete RFC 5011 implementation.

## Tamper evidence

The pending proposal fingerprint covers the canonical full anchor set. If any pending key tag, algorithm, digest type, or digest is modified without recomputing the fingerprint through the controlled staging path, state validation fails.

The rollover timing record is likewise bound to the full candidate-set fingerprint and will not continue its hold-down when the candidate changes.

These fingerprints are integrity bindings for workflow/state review; they are not substitutes for authenticating the external source that supplied a candidate root trust-anchor set.

## Current cryptographic policy interaction

Persistent anchors and rollover candidates are validated against Beacon's explicit DNSSEC cryptographic policy. The lifecycle code does not accept SHA-1 DNSSEC signing algorithms as DS delegation/trust-anchor algorithms, unsupported digest families, non-root lifecycle anchors, or empty trust sets.

The built-in KSK-2017 and KSK-2024 root DS records remain the current bootstrap set until a separately authenticated and explicitly approved lifecycle update is performed.

## Current acceptance boundary

This milestone provides:

- a versioned persistent state schema;
- owner-only atomic state-file writes;
- validated state loading;
- bootstrap conversion;
- complete-set update staging;
- one-pending-update enforcement;
- fingerprint-bound explicit approval;
- rejection without active-set mutation;
- tamper-evident pending state;
- restart-serializable candidate hold-down timing state;
- candidate-change rejection during hold-down;
- backwards-clock detection for persisted rollover timing; and
- deterministic source tests.

It does not yet provide:

- production runtime integration;
- automatic retrieval of root-anchor updates;
- authenticated HTTPS/XML trust-anchor distribution processing;
- complete RFC 5011 add/revoke/remove state transitions;
- monotonic-clock persistence across restarts;
- operator UI/API workflows;
- rollback/recovery acceptance on a target host; or
- production cutover authorization.

## Next lifecycle work

The next slice is authenticated candidate acquisition and a complete controlled rollover state machine without allowing remote data to bypass explicit GoreeCloud policy. That work must include source authentication, add/revoke/remove semantics, restart and recovery behavior, clock-anomaly handling, negative tests, and a controlled transition from source-level state management to isolated runtime acceptance.

## Production boundary

No production DNS service reads this state yet. Existing AdGuard Home, Unbound, GoreeCloud Network/NetBird DNS assignment, DNS rewrites, filtering, DHCP, Caddy, firewall state, authoritative DNS, encrypted DNS listeners, private trust anchors, client DNS behavior, credentials, and production cutover state remain unchanged.
