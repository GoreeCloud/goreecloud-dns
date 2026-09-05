#!/usr/bin/env python3
"""Fail-closed source validation for the GoreeCloud DNS Beacon Insights overview."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "client" / "src" / "components" / "Dashboard" / "index.tsx"
DASHBOARD_CSS = ROOT / "client" / "src" / "components" / "Dashboard" / "Dashboard.css"
E2E = ROOT / "client" / "tests" / "e2e" / "control-panel.spec.ts"


def require_file(path: Path) -> str:
    if not path.is_file():
        raise AssertionError(f"missing required file: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def require_markers(name: str, text: str, markers: list[str]) -> None:
    missing = [marker for marker in markers if marker not in text]
    if missing:
        raise AssertionError(f"{name} missing markers: {', '.join(missing)}")


def main() -> int:
    dashboard = require_file(DASHBOARD)
    dashboard_css = require_file(DASHBOARD_CSS)
    e2e = require_file(E2E)

    require_markers(
        "Beacon Insights dashboard",
        dashboard,
        [
            "Beacon Insights",
            "DNS Resolution Path",
            "Aggregate by default",
            "Current configured DNS data plane",
            "Native Beacon resolver stages are shown here only",
            "Open Query Log",
            "Manage Clients",
            "DNS Settings",
            "Filter Lists",
            'data-testid="beacon-query-total"',
            'data-testid="beacon-filtered-total"',
            'data-testid="beacon-client-total"',
            'data-testid="beacon-upstream-total"',
            "getClients();",
        ],
    )

    for private_default_panel in ("import Clients from './Clients'", "import QueriedDomains", "import BlockedDomains"):
        if private_default_panel in dashboard:
            raise AssertionError(f"default Beacon overview must not import raw-activity panel: {private_default_panel}")

    require_markers(
        "Beacon Insights responsive Glaze styling",
        dashboard_css,
        [
            ".beacon-dashboard",
            ".beacon-hero",
            ".beacon-metrics",
            ".beacon-resolution__track",
            ".beacon-service-grid",
            ".beacon-detail-grid",
            "var(--glaze-raised)",
            "var(--glaze-border)",
            "var(--glaze-target-min)",
            "overflow-wrap: anywhere",
            "@media (max-width: 599px)",
            "prefers-reduced-transparency: reduce",
            "prefers-contrast: more",
            "forced-colors: active",
        ],
    )

    require_markers(
        "Beacon Insights browser acceptance",
        e2e,
        [
            "Beacon Insights as an aggregate-first DNS overview",
            "DNS Resolution Path",
            "Aggregate by default",
            "beacon-query-total",
            "beacon-client-total",
            "beacon-upstream-total",
            "without horizontal overflow on compact screens",
            "document.documentElement.scrollWidth > document.documentElement.clientWidth",
        ],
    )

    print("GoreeCloud DNS Beacon Insights source contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
