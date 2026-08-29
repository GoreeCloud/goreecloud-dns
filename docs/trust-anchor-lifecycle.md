# Beacon Trust-Anchor Lifecycle

This document defines the current source-level lifecycle boundary for persistent DNSSEC root trust-anchor state in GoreeCloud Beacon.

## Purpose

The built-in `RootTrustAnchors()` set is a bootstrap source, not a permanent lifecycle mechanism. Beacon needs durable, recoverable trust-anchor state so a future production resolver can survive restarts, preserve reviewed rollover state, reject tampering, and avoid silently changing its DNSSEC trust basis because a network source or dependency changed.

The current implementation remains isolated from production DNS traffic. It provides controlled candidate staging, restart-serializable hold-down evidence, explicit review and activation, immutable recovery evidence, hash-chained lifecycle audit history, deterministic audit reconciliation, and an isolated activation/recovery rehearsal. It does not authorize unattended production rollover.

## Persistent trust-anchor state

The persisted schema is `goreecloud-beacon-trust-anchor-state/v1`.

State contains the active root DS trust-anchor set, the last update timestamp, and at most one pending candidate with its source, deterministic SHA-256 fingerprint, proposal time, and full anchor set. Only root (`.`) DS anchors are supported in this lifecycle store. Private routing trust anchors remain separate and are not mixed into root lifecycle state.

`TrustAnchorStore.Save` writes versioned JSON through an owner-only temporary file, syncs it, atomically replaces the destination, and enforces mode `0600`. `TrustAnchorStore.Load` validates schema, timestamps, anchor policy, uniqueness, digests, and pending fingerprints before accepting state.

## Candidate and review lifecycle

Candidate acquisition, DNSKEY-backed evidence, change planning, RFC 5011 revoke normalization, hold-down timing, staging, review, and activation are separate boundaries. A remotely observed candidate cannot directly replace the active set.

Activation requires the exact pending fingerprint, matching evidence source, completed hold-down state, and explicit manual-approval-ready review. The activation receipt contains review provenance and before/after fingerprints only; it contains no resolver query or client information.

## Recovery evidence

Before reviewed activation, Beacon can build a `goreecloud-beacon-trust-anchor-recovery/v1` recovery point containing the prior active set plus the exact pending fingerprint. `TrustAnchorRecoveryStore` persists that record separately as immutable owner-only evidence keyed by the candidate fingerprint.

Persisting a recovery point never activates or restores trust anchors. `RestoreTrustAnchorRecoveryPoint` is an explicit operator-controlled action and refuses recovery when a newer transition is pending, when the current set no longer matches the candidate named by the recovery record, or when the caller's expected current fingerprint differs.

## Lifecycle audit and reconciliation

`TrustAnchorLifecycleLog` stores owner-only JSONL lifecycle events with contiguous sequence numbers and a SHA-256 hash chain. Activation events bind review evidence, previous fingerprint, and activated fingerprint. Recovery events bind the explicitly recovered candidate fingerprint back to the restored previous fingerprint.

`PersistReviewedTrustAnchorActivation` validates that persisted lifecycle history ends at the state's current active fingerprint, persists the reviewed activation, then appends or idempotently reconciles the activation event. State and audit files are intentionally not represented as one atomic transaction. If state persistence succeeds but audit persistence fails, reconciliation is surfaced explicitly; rollback is never triggered automatically.

## Isolated activation/recovery rehearsal

`RunIsolatedTrustAnchorRecoveryRehearsal` provides a bounded exercise of the complete reviewed activation and explicit recovery path without touching production DNS state.

The caller must supply one existing rehearsal root. The trust-anchor state file, lifecycle log, and recovery-evidence directory must all be strict descendants of that root. Existing symbolic links anywhere along those store paths are rejected before persistence, preventing an apparently isolated path from redirecting writes outside the rehearsal boundary.

The rehearsal then:

1. validates the staged state and exact reviewed candidate;
2. creates, persists, and reloads the immutable recovery record;
3. performs the normal reviewed activation persistence and activation audit;
4. stops and returns reconciliation evidence if activation auditing is incomplete, without automatically recovering;
5. reloads the exact persisted recovery record;
6. explicitly restores and persists the previous anchor set;
7. appends a separate recovery lifecycle event;
8. reloads and verifies the hash-chained lifecycle history ends at the restored fingerprint; and
9. emits `goreecloud-beacon-trust-anchor-recovery-rehearsal-receipt/v1` with `production_cutover_authorized=false`.

The recovery leg is intentional because the function is specifically an activation-and-recovery rehearsal. It is not an automatic failure rollback policy and must not be reused to hide unresolved production activation or audit state.

## Security and privacy boundary

Lifecycle files are security-sensitive state and must remain owner-protected. Recovery and audit records do not contain DNS queries, client identifiers, resolver traffic, or unrestricted diagnostics. Fingerprints are integrity bindings for reviewed workflow state; they do not replace authentication of an external trust-anchor source.

Persistent lifecycle state must be included in future Everkeep backup/recovery acceptance and Wardveil Security evidence before any production use. Central status consumers should receive minimized evidence rather than raw anchor material or unrestricted lifecycle files.

## Current acceptance boundary

The current source milestone provides:

- versioned persistent root trust-anchor state;
- owner-only atomic state writes;
- authenticated-candidate and DNSKEY evidence boundaries;
- deterministic change planning and revoke normalization;
- restart-serializable hold-down timing;
- fingerprint- and source-bound staging/review/activation;
- immutable owner-only recovery evidence;
- explicit recovery with exact-current-state checks;
- hash-chained activation and recovery audit events;
- deterministic activation audit reconciliation; and
- an isolated, path-bounded activation/recovery rehearsal with no automatic rollback.

It does not yet provide production runtime integration, unattended network-driven rollover, production source credentials, production recovery acceptance, production Everkeep/Wardveil evidence, operator UI/API workflows, or production cutover authorization.

## Production boundary

No production DNS service reads the rehearsal stores or uses the rehearsal transaction. Existing AdGuard Home, Unbound, GoreeCloud Network/NetBird DNS assignment, DNS rewrites, filtering, DHCP, Caddy, firewall state, authoritative DNS, encrypted DNS listeners, private trust anchors, client DNS behavior, credentials, and production trust-anchor state remain unchanged.
