# GoreeCloud DNS — Glaze UI 1.0 Conformance

## Status

GoreeCloud DNS is an active Glaze UI 1.0 consumer implementation. This document records source-level conformance for the first additive application-wide design layer. It does not classify the product Stable and does not replace compiled visual acceptance.

## Canonical Target

- Design system: Glaze UI
- Target version: 1.0.0
- Product: GoreeCloud DNS
- Implementation model: local web consumer layer over the inherited AdGuard Home frontend
- Remote UI dependencies introduced by Glaze UI: none

## Surface Hierarchy

The application maps the Glaze UI hierarchy as follows:

- **Canvas** — atmospheric application background.
- **Solid** — readability-first controls and fallback surfaces.
- **Raised** — cards and ordinary elevated content.
- **Glaze** — selective translucent header/navigation treatment.
- **Overlay** — dialogs and menus requiring stronger separation.

The implementation deliberately avoids applying glass treatment everywhere. Glaze surfaces have solid fallbacks when transparency or backdrop filtering is unavailable or unsuitable.

## Semantic Tokens

`client/src/glaze-ui.css` defines product-local semantic roles for canvas, solid, raised, glaze, overlay, text, muted text, border, accent, success, warning, danger, focus, geometry, depth, target size, spacing, and motion. Existing inherited CSS variables are bridged onto these roles to support gradual migration instead of a destabilizing full rewrite.

## Interaction Contract

The current foundation establishes consistent rounded control geometry, semantic accent treatment, visible `:focus-visible` focus, coarse-pointer minimum target sizing, and the canonical Glaze motion vocabulary:

- Instant: 90 ms
- Fast: 160 ms
- Standard: 220 ms
- Emphasized: 320 ms

Component-by-component interaction-state review remains required as inherited surfaces are migrated.

## Adaptive Layout Contract

The Glaze consumer layer explicitly records all four adaptive ranges:

- Compact: through 599 px
- Medium: 600–1023 px
- Expanded: 1024–1439 px
- Wide: 1440 px and above

The first pass adjusts container spacing and wide-layout bounds. Deeper navigation and data-density transformations remain follow-up work.

## Accessibility and Resilience

The source layer includes:

- visible keyboard focus;
- 44 px minimum coarse-pointer targets;
- reduced-motion handling;
- reduced-transparency handling;
- no-backdrop-filter solid fallback;
- increased-contrast handling;
- forced-colors handling;
- local/system typography only;
- no remote font, icon, analytics, tracking, or presentation runtime introduced by this layer.

## Appearance

The inherited application already exposes light and dark theme behavior. The Glaze consumer layer maps both themes to semantic roles. System appearance and explicit preference behavior must be reviewed in runtime acceptance before Stable classification.

## Product Identity

GoreeCloud DNS retains a DNS/security-specific product personality while using shared Glaze UI semantics. The application shell now uses GoreeCloud DNS titles and a GoreeCloud DNS header mark. A complete canonical icon/favicon asset family remains follow-up work.

## Stable-Release Boundary

Source conformance does not establish visual completion. Before GoreeCloud DNS can be classified Stable, representative acceptance must cover light and dark appearance, Compact and Expanded layouts, keyboard navigation, zoom/reflow, contrast, screen-reader semantics, reduced-motion behavior, reduced-transparency fallback, forms, tables, dialogs, menus, query-log surfaces, filtering/settings surfaces, and installation/authentication flows.

No production DNS cutover is authorized by this conformance record.
