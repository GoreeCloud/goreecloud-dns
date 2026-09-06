# GoreeCloud DNS — Glaze UI 1.1 Conformance

## Status

GoreeCloud DNS is an active Glaze UI 1.1 consumer implementation. This document records source-level conformance for the additive application-wide design layer. It does not classify the product Stable and does not replace compiled visual acceptance.

## Canonical Target

- Design system: Glaze UI
- Target version: 1.1.0
- Canonical repository: GoreeCloud/glaze-ui
- Reviewed Stable revision: 5c8320de4f770614a3e2bcf9de2a27f7fcfd920c
- Product: GoreeCloud DNS
- Implementation model: local web consumer layer over the inherited AdGuard Home frontend
- Remote UI dependencies introduced by Glaze UI: none

## Surface Hierarchy

The application maps the Glaze UI hierarchy as follows:

- **Canvas** — atmospheric application and authentication/setup backgrounds.
- **Solid** — readability-first controls and fallback surfaces.
- **Raised** — cards, login form, setup container, settings regions, query-log toolbar, tables, and ordinary elevated content.
- **Glaze** — selective translucent header/navigation treatment.
- **Overlay** — dialogs and menus requiring stronger separation, with the 1.1 modal-scrim semantic role.

The implementation deliberately avoids applying glass treatment everywhere. Glaze surfaces have solid fallbacks when transparency or backdrop filtering is unavailable or unsuitable.

## Semantic Tokens

`client/src/glaze-ui.css` defines product-local semantic roles for canvas, solid, raised, glaze, overlay, text, muted text, border, accent, on-accent, info, success, warning, danger, focus, modal scrim, geometry, depth, target size, icon size, spacing, typography, motion, layering, adaptive gutters, and safe-area behavior. Existing inherited CSS variables are bridged onto these roles to support gradual migration instead of a destabilizing full rewrite.

Glaze UI 1.1 state layers are represented explicitly for hover, pressed, focus, and selected interaction states. The consumer also records compact and comfortable density semantics so dense administrative screens can remain efficient for pointer use while becoming touch-safe on coarse-pointer devices.

`client/src/glaze-ui-components.css` extends the semantic layer across cards, tables, ReactTable instances, forms, dropdowns, pagination, alerts, badges, dialogs, settings regions, and dense Query Log surfaces.

## Entrypoint Coverage

The dashboard, initial setup flow, and authentication flow all load the same Glaze UI base/component layers and GoreeCloud product-identity adapter. Source validators fail closed if any of these three independently bundled frontend entrypoints loses those imports.

The setup and authentication surfaces additionally map their inherited presentation onto Glaze semantic values rather than legacy hard-coded card radius, shadow, progress-track, error, or accent values. The initial-setup progress indicator exposes native progressbar semantics with localized naming and explicit current/minimum/maximum values, while the authentication password-help disclosure exposes its expanded state and controlled help region without changing the inherited reset workflow. The setup configuration validation debounce is memoized and canceled on teardown so delayed validation work does not outlive the setup component or get recreated on each render. Setup credential creation also declares the confirmation field dependent on the password field, forcing cross-field revalidation when the password changes after confirmation and preventing stale valid confirmation state from authorizing submission.

## Dense Administration Coverage

General Settings, advanced settings regions, inherited responsive tables, ReactTable surfaces, and the Query Log now share a stronger Raised-region treatment without changing inherited handlers, state management, filtering semantics, refresh behavior, DNS APIs, or configuration writes.

Dense tables use semantic headers, stable overflow behavior, compact row spacing for pointer-heavy administration, comfortable row spacing on coarse-pointer devices, 44-pixel pagination targets, state-layer hover treatment, reduced-motion handling, reduced-transparency fallback, and forced-colors resilience. Compact layouts keep tables scrollable rather than compressing data into unreadable columns.

The Query Log search/status toolbar uses canonical target sizing, semantic controls, Compact spacing, and 1.1 interaction-state semantics. The search region, response-status selector, icon-only refresh action, and clear-search action expose explicit accessibility semantics. The clear-search affordance is a native keyboard-operable button rather than a click-only container. The strict-search guidance remains available as a visual tooltip, while the same localized guidance is also associated directly with the search field through `aria-describedby`, so understanding the search syntax does not depend on hover or pointer interaction. Decorative search/refresh/clear/help artwork is removed from the accessibility tree.

Advanced settings also include source-level accessibility hardening for DNS access controls, client add/edit dialogs, encryption validation feedback, DHCP interface validation, DHCP lease actions, DHCP range groups, and the shared `Input` control. The DHCP interface selector exposes invalid state and its validation message through `aria-invalid` and `aria-describedby`, while the lease table uses accessible labels for icon-only actions and safely handles an absent leases array before pagination decisions. IPv4 and IPv6 range controls expose explicit named group semantics rather than relying on unassociated visual labels.

The shared `Input` control now establishes stable input IDs from the explicit `id` or field `name`, connects visible labels with `htmlFor`, links descriptions and errors through `aria-describedby`, exposes validation state through `aria-invalid`, and marks visible validation feedback as an alert. This improves every current consumer of the shared control without changing form values or backend behavior.

This is presentation, semantics, defensive frontend behavior, setup lifecycle hardening, and setup form-integrity hardening only. It does not alter query collection, retention, filtering decisions, DNS processing, client policy, upstream selection, cache behavior, encryption behavior, DHCP allocation behavior, authentication processing, password-reset behavior, or backend configuration behavior.

## Interaction Contract

The current foundation establishes consistent rounded control geometry, semantic accent treatment, visible `:focus-visible` focus, coarse-pointer minimum target sizing, hover/pressed/selected state layers, and the canonical Glaze motion vocabulary:

- Instant: 90 ms
- Fast: 160 ms
- Standard: 220 ms
- Emphasized: 320 ms

The 1.1 standard easing role is used for transition timing. Component-by-component runtime review remains required as inherited surfaces are migrated.

## Adaptive Layout Contract

The Glaze consumer layer explicitly records all four adaptive ranges:

- Compact: through 599 px
- Medium: 600–1023 px
- Expanded: 1024–1439 px
- Wide: 1440 px and above

Application containers now use the 1.1 adaptive gutter semantics and safe-area insets rather than one repeated inherited spacing value. The current pass covers application container spacing, wide-layout bounds, setup-card behavior, authentication-card behavior, navigation adaptation, Query Log controls, and dense table overflow at Compact widths.

## Accessibility and Resilience

The source layer includes:

- visible keyboard focus;
- 44 px minimum and 48 px comfortable target semantics;
- a native keyboard-operable mobile navigation button with an accessible name, `aria-expanded`, and `aria-controls` linked to the primary navigation landmark;
- a named primary `nav` landmark whose identifier is protected by source validation;
- decorative mobile-navigation and navigation-item glyphs hidden from assistive technology;
- a named initial-setup progressbar with explicit current, minimum, and maximum values;
- authentication password-help disclosure semantics using `aria-expanded` and `aria-controls` with a stable controlled help-region ID;
- memoized, teardown-cancelled setup configuration validation debounce behavior;
- setup password-confirmation dependency validation so changing the password revalidates confirmation rather than retaining stale form validity;
- shared input label, description, validation-state, and error relationships;
- explicit Query Log search/status/refresh/clear accessibility semantics;
- a native keyboard-operable Query Log clear-search action with an accessible label;
- Query Log strict-search guidance directly associated with the search input through `aria-describedby` while retaining the visual tooltip;
- decorative Query Log search, refresh, clear, and help glyphs hidden from assistive technology;
- DNS access-form description relationships;
- client-modal title labeling;
- certificate and private-key validation status announcements;
- DHCP interface error relationships and alert semantics;
- explicit IPv4 and IPv6 DHCP range-group naming;
- accessible DHCP lease action labeling with decorative icons hidden from assistive technology;
- touch-safe dense-table and pagination treatment;
- reduced-motion handling;
- reduced-transparency handling;
- no-backdrop-filter solid fallback;
- increased-contrast handling;
- forced-colors handling;
- safe-area-aware application/header gutters;
- local/system typography only;
- no remote font, icon, analytics, tracking, or presentation runtime introduced by this layer.

Setup and authentication surfaces preserve the existing mobile input anti-zoom accommodation while gaining semantic contrast, forced-colors behavior, Glaze surface fallbacks, explicit setup progress semantics, deterministic debounced validation cleanup, cross-field credential validation, and stateful password-help disclosure semantics.

## Appearance

The inherited application already exposes light and dark theme behavior. The Glaze consumer layer maps both themes to semantic roles while retaining a DNS-specific GoreeCloud accent. System appearance and explicit preference behavior must be reviewed in runtime acceptance before Stable classification.

## Product Identity

GoreeCloud DNS retains a DNS/security-specific product personality while using shared Glaze UI semantics. The application shell uses GoreeCloud DNS titles and a GoreeCloud DNS header mark.

`client/src/productIdentity.ts` adapts exact inherited `AdGuard Home` localization self-references to `GoreeCloud DNS`. It intentionally does not generically replace `AdGuard`, upstream organization names, protocol terminology, filtering syntax, licensing, or provenance. The dashboard, setup, and login entrypoints all load this adapter.

The browser-facing SVG mark is established as the current canonical source asset. Legacy inherited binary compatibility icons remain review items until safe GoreeCloud-derived replacements are generated and validated for every required platform surface.

## Validation Boundary

`scripts/validate_glaze_ui.py` and `scripts/validate_product_identity.py` are source-controlled fail-closed contracts. The Glaze validator requires the Stable 1.1 version claim, state layers, icon and density semantics, adaptive gutters, safe-area markers, primary-navigation button/landmark semantics and minimum-target styling, setup validation lifecycle stability, setup progressbar semantics, authentication password-help disclosure semantics, dense settings/table coverage, reusable input accessibility, Query Log accessibility semantics including the keyboard-operable clear-search action and programmatically associated strict-search guidance, advanced Settings semantics, DNS access-control relationships, client-modal labeling, encryption status announcements, DHCP validation/action accessibility, DHCP range-group naming, and resilience behavior. The setup password-confirmation dependency is additionally part of source review and executable typecheck/form acceptance until it is incorporated into the fail-closed validator. Executable GitHub Actions status must still be observed separately; source-marker validation does not substitute for lint, typecheck, tests, production build, or compiled visual acceptance.

## Stable-Release Boundary

Source conformance does not establish visual completion. Before GoreeCloud DNS can be classified Stable, representative acceptance must cover light and dark appearance, Compact and Expanded layouts, keyboard navigation, zoom/reflow, contrast, screen-reader semantics, reduced-motion behavior, reduced-transparency fallback, forms, tables, dialogs, menus, query-log surfaces, DNS/advanced settings, client management, encryption, DHCP, installation, and authentication flows, including changing the setup password after confirmation and verifying that mismatched credentials block submission.

No production DNS cutover is authorized by this conformance record.
