---
title: "GoreeCloud DNS Feature Roadmap"
document_type: "Feature Roadmap"
version: "v1.0"
status: "Active"
classification: "Internal"
last_updated: "2026-09-15"
application_service: "GoreeCloud DNS"
authoritative_project_record: "Project Specification — DNS v1.0"
---

# GoreeCloud DNS Feature Roadmap

## Purpose

This is the canonical editable feature-roadmap source for GoreeCloud DNS. It records current planned and recommended feature work without replacing the authoritative project specification, verified repository implementation evidence, release gates, or GoreeCloud Tasks Management.

## Maintenance and synchronization

This repository `FEATURE-ROADMAP.md` and the corresponding Markdown representation under `GoreeCloud/Feature Roadmap/GoreeCloud DNS` must remain materially synchronized with one another and with the authoritative project or service record. Update both copies whenever feature scope, priority, dependency, implementation status, cancellation, supersession, recommendation, or verification state materially changes.

No feature may be represented as complete or Stable solely because it appears in this roadmap. Completion and lifecycle claims require the applicable authoritative implementation, validation, review, release, and production evidence.

At each material feature change, reconcile this roadmap against the current authoritative project record, repository implementation state, applicable Platform-System requirements, and GoreeCloud Tasks Management. Missing obligations, stale status, duplicated work, roadmap drift, or undocumented disposition changes are defects to correct.

## Roadmap control

| Field | Value |
| --- | --- |
| Application / Service | GoreeCloud DNS |
| Authoritative project record | Project Specification — DNS (internal version v1.0) |
| Canonical repository | `GoreeCloud/goreecloud-dns` |
| Repository control | `FEATURE-ROADMAP.md` |
| Drive representation | `GoreeCloud/Feature Roadmap/GoreeCloud DNS/FEATURE-ROADMAP.md` |

## Current obligations

| ID | Feature / obligation | Priority | Current state |
| --- | --- | --- | --- |
| FR-001 | Reconcile and maintain every current planned or recommended GoreeCloud DNS feature from the authoritative project record and verified repository evidence in this roadmap. | High | Ongoing control |
| FR-002 | Move actionable feature obligations into GoreeCloud Tasks Management when required, preserving priority, dependency, and lifecycle disposition. | High | Ongoing control |
| FR-003 | Do not mark features implemented, complete, cancelled, or superseded without authoritative evidence and synchronized repository/Drive roadmap updates. | High | Ongoing control |
| FR-004 | Implement the expanded GoreeCloud DNS + GoreeCloud Beacon capability program defined by Project Specification — DNS v1.0 §34. The program covers Beacon Shield, Policy Profiles, Resolver, Cache, Zones, Secure DNS, Horizon, DHCP, Cluster, Console, API, Identity, Insights, Extensions, privacy controls, family controls, managed catalogs/lists, service discovery, and governed GoreeCloud ecosystem boundaries. | High | Requirements approved; phased Development. Managed filter-list recovery/import through Draft PR #17 is repository-validated at its exact head; redirect-policy hardening is under validation in stacked Draft PR #18. Full implementation and production acceptance remain pending. |
| FR-005 | Keep this repository roadmap materially synchronized with Project Specification — DNS v1.0 §34 and the Drive roadmap representation, and verify the synchronized records after material scope changes. | High | Repository roadmap restored in Draft PR #18 after a verified missing-file drift defect; Drive Markdown synchronization is required in the same workflow. |

## Lifecycle boundary

Roadmap state is planning and coordination evidence, not production acceptance. Draft pull requests, passing repository tests, roadmap entries, or documented implementation candidates do not authorize production DNS cutover, retirement of AdGuard Home or Unbound, Release Candidate promotion, or Stable status. Those gates remain fail-closed until their own authoritative acceptance evidence exists.
