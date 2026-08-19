#!/usr/bin/env python3
"""Fail-closed source validation for GoreeCloud DNS Glaze UI integration."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
CSS = ROOT / "client" / "src" / "glaze-ui.css"
COMPONENT_CSS = ROOT / "client" / "src" / "glaze-ui-components.css"
QUERY_LOG_FILTER = ROOT / "client" / "src" / "components" / "Logs" / "Filters" / "Form.tsx"
QUERY_LOG_HEADER = ROOT / "client" / "src" / "components" / "Logs" / "Filters" / "index.tsx"
ENTRYPOINTS = (
    ROOT / "client" / "src" / "index.tsx",
    ROOT / "client" / "src" / "install" / "index.tsx",
    ROOT / "client" / "src" / "login" / "index.tsx",
)
DOC = ROOT / "docs" / "glaze-ui-conformance.md"


def require_file(path: Path) -> str:
    if not path.is_file():
        raise AssertionError(f"missing required file: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def require_markers(name: str, text: str, markers: list[str]) -> None:
    missing = [marker for marker in markers if marker not in text]
    if missing:
        raise AssertionError(f"{name} missing markers: {', '.join(missing)}")


def main() -> int:
    css = require_file(CSS)
    component_css = require_file(COMPONENT_CSS)
    query_log_filter = require_file(QUERY_LOG_FILTER)
    query_log_header = require_file(QUERY_LOG_HEADER)
    doc = require_file(DOC)

    require_markers(
        "glaze-ui.css",
        css,
        [
            "--glaze-version: 1.1.0",
            "--glaze-canvas:",
            "--glaze-solid:",
            "--glaze-raised:",
            "--glaze-glaze:",
            "--glaze-overlay:",
            "--glaze-on-accent:",
            "--glaze-info:",
            "--glaze-scrim:",
            "--glaze-state-hover: 0.08",
            "--glaze-state-pressed: 0.12",
            "--glaze-state-focus: 0.14",
            "--glaze-state-selected: 0.12",
            "--glaze-target-min: 44px",
            "--glaze-target-comfortable: 48px",
            "--glaze-icon-sm: 16px",
            "--glaze-icon-md: 20px",
            "--glaze-icon-lg: 24px",
            "--glaze-icon-xl: 32px",
            "--glaze-density-compact-gap: 8px",
            "--glaze-density-comfortable-gap: 12px",
            "--glaze-gutter-compact: 16px",
            "--glaze-gutter-medium: 24px",
            "--glaze-gutter-expanded: 32px",
            "--glaze-gutter-wide: 40px",
            "env(safe-area-inset-top, 0px)",
            "env(safe-area-inset-left, 0px)",
            "--glaze-motion-instant: 90ms",
            "--glaze-motion-fast: 160ms",
            "--glaze-motion-standard: 220ms",
            "--glaze-motion-emphasized: 320ms",
            "--glaze-ease-standard:",
            "@media (max-width: 599px)",
            "@media (min-width: 600px) and (max-width: 1023px)",
            "@media (min-width: 1024px) and (max-width: 1439px)",
            "@media (min-width: 1440px)",
            "prefers-reduced-motion: reduce",
            "prefers-reduced-transparency: reduce",
            "prefers-contrast: more",
            "forced-colors: active",
            "@supports not ((backdrop-filter: blur(1px))",
            ":focus-visible",
        ],
    )

    require_markers(
        "glaze-ui-components.css",
        component_css,
        [
            ".table",
            ".table-responsive",
            ".ReactTable",
            ".form-control",
            ".dropdown-item",
            ".btn-outline-secondary",
            ".pagination .page-link",
            ".modal-header",
            ".close",
            ".box-body--settings",
            ".page-header--logs",
            ".logs__refresh",
            ".logs__table",
            "var(--glaze-state-hover)",
            "var(--glaze-state-pressed)",
            "var(--glaze-density-compact-gap)",
            "var(--glaze-density-comfortable-gap)",
            "scrollbar-gutter: stable",
            "prefers-reduced-motion: reduce",
            "prefers-reduced-transparency: reduce",
            "forced-colors: active",
        ],
    )

    require_markers(
        "Query Log filter accessibility",
        query_log_filter,
        [
            'role="search"',
            "aria-label={t('query_log')}",
            "register('response_status')",
        ],
    )

    require_markers(
        "Query Log header accessibility",
        query_log_header,
        [
            "aria-label={t('refresh_btn')}",
            'aria-hidden="true"',
            'focusable="false"',
        ],
    )

    for entrypoint in ENTRYPOINTS:
        entry = require_file(entrypoint)
        require_markers(
            str(entrypoint.relative_to(ROOT)),
            entry,
            [
                "glaze-ui.css",
                "glaze-ui-components.css",
            ],
        )

    require_markers(
        "glaze-ui-conformance.md",
        doc,
        [
            "Glaze UI 1.1",
            "Target version: 1.1.0",
            "Canvas",
            "Solid",
            "Raised",
            "Glaze",
            "Overlay",
            "state layers",
            "compact and comfortable density",
            "safe-area",
            "Compact: through 599 px",
            "Medium: 600–1023 px",
            "Expanded: 1024–1439 px",
            "Wide: 1440 px and above",
            "No production DNS cutover is authorized",
        ],
    )

    forbidden = [
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "unpkg.com",
        "jsdelivr.net",
        "cdnjs.cloudflare.com",
    ]
    combined = css + "\n" + component_css + "\n" + doc
    leaked = [value for value in forbidden if value in combined]
    if leaked:
        raise AssertionError(f"remote presentation dependency found: {', '.join(leaked)}")

    print("GoreeCloud DNS Glaze UI 1.1 source validation passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"Glaze UI validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
