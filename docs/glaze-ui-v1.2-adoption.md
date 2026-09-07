# GoreeCloud DNS — GLAZE UI V1.2 Adoption Boundary

## Current authority

GLAZE UI V1.2 / 1.2.0 is the current Stable GoreeCloud design-system target. GoreeCloud DNS must independently adopt that target and produce repository-local evidence for every applicable design, interaction, accessibility, responsive/form-factor, platform, performance, and production requirement.

The current Stable Glaze UI authority does not automatically make GoreeCloud DNS V1.2-conformant or production-eligible.

## Current repository state

This GoreeCloud DNS development line retains source-level Glaze UI work that was built and validated against the earlier V1.1 baseline. That source evidence remains useful migration evidence, but it is not relabeled as V1.2 evidence.

The machine-readable Platform Contract therefore records:

- required Glaze UI target: `1.2.0`;
- Glaze UI integration result: `applicable-migration-required`;
- accepted Glaze UI version: unset;
- overall platform conformance: `nonconformant`.

`docs/glaze-ui-conformance.md` remains the repository record for the existing V1.1 source baseline until a controlled V1.2 adoption replaces or supersedes that evidence on an exact revision.

## Required V1.2 adoption work

Before GoreeCloud DNS may claim current Glaze UI conformance, the applicable UI surfaces must be reviewed and migrated against the authoritative V1.2 contracts rather than by version-label replacement or visual similarity alone. Evidence must include, as applicable:

- V1.2 material, semantic, component, interaction, and adaptive-layout mapping;
- Reduced Motion, Reduced Transparency, Increased Contrast, and Forced Colors behavior;
- keyboard, pointer, touch, focus, and assistive-input behavior;
- 200% text/reflow and applicable RTL behavior;
- responsive and supported form-factor acceptance;
- exact source/revision provenance for the consumed V1.2 implementation;
- performance and graceful-degradation behavior;
- representative rendered/runtime acceptance for the exact DNS candidate.

Any retained inherited frontend behavior must remain subordinate to GoreeCloud product identity, accessibility, privacy, security, and authority boundaries.

## Lifecycle boundary

This record changes the required design-system target only. It does not claim that V1.2 is already implemented or accepted in GoreeCloud DNS, does not change GoreeCloud DNS from Development, does not make the Platform Contract conformant, and does not authorize production DNS cutover, release promotion, or Stable classification.
