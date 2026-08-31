# Beacon migration readiness

## Purpose

`internal/gcdns/migration_readiness.go` defines the fail-closed evidence boundary for advancing GoreeCloud Beacon toward an explicitly approved production migration rehearsal.

The contract is `goreecloud-beacon-migration-evidence/v1`. Evidence is bound to one exact source revision and one immutable runtime-artifact SHA-256. The evaluator records readiness only; it does not start listeners, modify DNS configuration, change trust anchors, alter client assignments, or transfer production DNS authority.

## Required evidence

Migration-rehearsal eligibility requires all of the following evidence for the exact candidate revision and artifact:

- resolver behavior/parity validation for the production-required DNS feature set;
- private-recursion validation;
- DNSSEC validation;
- successful isolated trust-anchor recovery rehearsal;
- restart and failure-mode validation;
- cache-behavior validation;
- encrypted-DNS validation;
- backup/restore proof;
- rollback rehearsal;
- privacy-safe observability validation;
- Privacy Shield validation;
- Wardveil Security validation;
- Everkeep validation;
- validation against the current Stable Glaze UI contract for user-facing administration surfaces.

The current validated Glaze UI Stable baseline is 2.1.0. Historical Glaze UI 1.x and 2.0.0 remain migration, rollback, or audit context only and cannot satisfy a current Beacon administration-surface acceptance claim.

## Safety boundary

The evaluator rejects malformed source/artifact identities and rejects any evidence object that claims `production_cutover_authorized=true`.

Even complete evidence only produces `eligible_for_migration_rehearsal=true`. `production_cutover_authorized` remains false in every decision.

Production AdGuard Home, Unbound, Network/Conduit DNS assignment, filtering, DHCP, authoritative DNS, encrypted DNS endpoints, credentials, client behavior, listeners, forwarding/stub targets, private zones, and production trust-anchor state remain unchanged until a separately approved migration is validated.
