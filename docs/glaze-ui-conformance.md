# GoreeCloud DNS — Glaze UI 1.0 Conformance

## Status

GoreeCloud DNS is an active Glaze UI 1.0 consumer implementation. This document records source-level conformance for the additive application-wide design layer. It does not classify the product Stable and does not replace compiled visual acceptance.

## Canonical Target

- Design system: Glaze UI
- Target version: 1.0.0
- Canonical repository: GoreeCloud/glaze-ui
- Reviewed canonical revision: d6e446fd8ef251259d16368d50aad90d9287a774
- Product: GoreeCloud DNS
- Implementation model: local web consumer layer over the inherited AdGuard Home frontend
- Remote UI dependencies introduced by Glaze UI: none

## Surface Hierarchy

The application maps the Glaze UI hierarchy as follows:

- **Canvas** — atmospheric application and authentication/setup backgrounds.
- **Solid** — readability-first controls and fallback surfaces.
- **Raised** — cards, login form, setup container, settings regions, query-log toolbar, and ordinary elevated content.
- **Glaze** — selective translucent header/navigation treatment.
- **Overlay** — dialogs and menus requiring stronger separation.

The implementation deliberately avoids applying glass treatment everywhere. Glaze surfaces have solid fallbacks when transparency or backdrop filtering is unavailable or unsuitable.

## Semantic Tokens

`client/src/glaze-ui.css` defines product-local semantic roles for canvas, solid, raised, glaze, overlay, text, muted text, border, accent, success, warning, danger, focus, geometry, depth, target size, spacing, and motion. Existing inherited CSS variables are bridged onto these roles to support gradual migration instead of a destabilizing full rewrite.

`client/src/glaze-ui-components.css` extends the semantic layer across cards, tables, forms, dropdowns, pagination, alerts, badges, dialogs, settings regions, and dense Query Log surfaces.

## Entrypoint Coverage

The dashboard, initial setup flow, and authentication flow all load the same Glaze UI base/component layers and GoreeCloud product-identity adapter. Source validators fail closed if any of these three independently bundled frontend entrypoints loses those imports.

The setup and authentication surfaces additionally map their inherited presentation onto Glaze semantic values rather than legacy hard-coded card radius, shadow, progress-track, error, or accent values.

## Dense Administration Coverage

The current source layer gives General Settings content and the Query Log dedicated Raised-region treatment without changing inherited handlers, state management, filtering semantics, refresh behavior, or DNS APIs. The Query Log search/status toolbar uses canonical target sizing, semantic controls, Compact spacing, reduced-motion handling, and forced-colors fallback. The search region, response-status selector, and icon-only refresh action now expose explicit accessibility semantics, with decorative refresh artwork removed from the accessibility tree.

This is presentation and semantics work only. It does not alter query collection, retention, filtering decisions, DNS processing, client policy, or backend configuration behavior.

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

The current pass covers application container spacing, wide-layout bounds, setup-card behavior, authentication-card behavior, navigation adaptation, and the Query Log toolbar at Compact widths. Deeper per-table and advanced-settings density review remains follow-up work.

## Accessibility and Resilience

The source layer includes:

- visible keyboard focus;
- 44 px minimum and 48 px comfortable target semantics;
- explicit Query Log search/status/refresh accessibility semantics;
- reduced-motion handling;
- reduced-transparency handling;
- no-backdrop-filter solid fallback;
- increased-contrast handling;
- forced-colors handling;
- local/system typography only;
- no remote font, icon, analytics, tracking, or presentation runtime introduced by this layer.

Setup and authentication surfaces preserve the existing mobile input anti-zoom accommodation while gaining semantic contrast, forced-colors behavior, and Glaze surface fallbacks.

## Appearance

The inherited application already exposes light and dark theme behavior. The Glaze consumer layer maps both themes to semantic roles. System appearance and explicit preference behavior must be reviewed in runtime acceptance before Stable classification.

## Product Identity

GoreeCloud DNS retains a DNS/security-specific product personality while using shared Glaze UI semantics. The application shell uses GoreeCloud DNS titles and a GoreeCloud DNS header mark.

`client/src/productIdentity.ts` adapts exact inherited `AdGuard Home` localization self-references to `GoreeCloud DNS`. It intentionally does not generically replace `AdGuard`, upstream organization names, protocol terminology, filtering syntax, licensing, or provenance. The dashboard, setup, and login entrypoints all load this adapter.

The browser-facing SVG mark is established as the current canonical source asset. Legacy inherited binary compatibility icons remain review items until safe GoreeCloud-derived replacements are generated and validated for every required platform surface.

## Validation Boundary

`scripts/validate_glaze_ui.py` and `scripts/validate_product_identity.py` are source-controlled fail-closed contracts. The Glaze validator now also requires the dense settings/Query Log surface markers and Query Log accessibility semantics introduced by this pass. Executable GitHub Actions status must still be observed separately; source-marker validation does not substitute for lint, typecheck, tests, production build, or compiled visual acceptance.

## Stable-Release Boundary

Source conformance does not establish visual completion. Before GoreeCloud DNS can be classified Stable, representative acceptance must cover light and dark appearance, Compact and Expanded layouts, keyboard navigation, zoom/reflow, contrast, screen-reader semantics, reduced-motion behavior, reduced-transparency fallback, forms, tables, dialogs, menus, query-log surfaces, filtering/settings surfaces, and installation/authentication flows.

No production DNS cutover is authorized by this conformance record.
