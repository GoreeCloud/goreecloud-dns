#!/usr/bin/env python3
"""Fail-closed source validation for GoreeCloud DNS Glaze UI integration."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
CSS = ROOT / "client" / "src" / "glaze-ui.css"
COMPONENT_CSS = ROOT / "client" / "src" / "glaze-ui-components.css"
SETTINGS_CSS = ROOT / "client" / "src" / "components" / "Settings" / "Settings.css"
HEADER = ROOT / "client" / "src" / "components" / "Header" / "index.tsx"
HEADER_MENU = ROOT / "client" / "src" / "components" / "Header" / "Menu.tsx"
HEADER_CSS = ROOT / "client" / "src" / "components" / "Header" / "Header.css"
SETUP = ROOT / "client" / "src" / "install" / "Setup" / "index.tsx"
SETUP_PROGRESS = ROOT / "client" / "src" / "install" / "Setup" / "Progress.tsx"
SETUP_AUTH = ROOT / "client" / "src" / "install" / "Setup" / "Auth.tsx"
LOGIN = ROOT / "client" / "src" / "login" / "Login" / "index.tsx"
INPUT_CONTROL = ROOT / "client" / "src" / "components" / "ui" / "Controls" / "Input.tsx"
DNS_ACCESS_FORM = ROOT / "client" / "src" / "components" / "Settings" / "Dns" / "Access" / "Form.tsx"
CLIENT_MODAL = ROOT / "client" / "src" / "components" / "Settings" / "Clients" / "Modal.tsx"
CERT_STATUS = ROOT / "client" / "src" / "components" / "Settings" / "Encryption" / "CertificateStatus.tsx"
KEY_STATUS = ROOT / "client" / "src" / "components" / "Settings" / "Encryption" / "KeyStatus.tsx"
DHCP_INTERFACES = ROOT / "client" / "src" / "components" / "Settings" / "Dhcp" / "Interfaces.tsx"
DHCP_LEASES = ROOT / "client" / "src" / "components" / "Settings" / "Dhcp" / "Leases.tsx"
DHCP_V4_FORM = ROOT / "client" / "src" / "components" / "Settings" / "Dhcp" / "FormDHCPv4.tsx"
DHCP_V6_FORM = ROOT / "client" / "src" / "components" / "Settings" / "Dhcp" / "FormDHCPv6.tsx"
QUERY_LOG_FILTER = ROOT / "client" / "src" / "components" / "Logs" / "Filters" / "Form.tsx"
QUERY_LOG_SEARCH = ROOT / "client" / "src" / "components" / "Logs" / "Filters" / "SearchField.tsx"
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
    settings_css = require_file(SETTINGS_CSS)
    header = require_file(HEADER)
    header_menu = require_file(HEADER_MENU)
    header_css = require_file(HEADER_CSS)
    setup = require_file(SETUP)
    setup_progress = require_file(SETUP_PROGRESS)
    setup_auth = require_file(SETUP_AUTH)
    login = require_file(LOGIN)
    input_control = require_file(INPUT_CONTROL)
    dns_access_form = require_file(DNS_ACCESS_FORM)
    client_modal = require_file(CLIENT_MODAL)
    cert_status = require_file(CERT_STATUS)
    key_status = require_file(KEY_STATUS)
    dhcp_interfaces = require_file(DHCP_INTERFACES)
    dhcp_leases = require_file(DHCP_LEASES)
    dhcp_v4_form = require_file(DHCP_V4_FORM)
    dhcp_v6_form = require_file(DHCP_V6_FORM)
    query_log_filter = require_file(QUERY_LOG_FILTER)
    query_log_search = require_file(QUERY_LOG_SEARCH)
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
        "Settings semantic accessibility",
        settings_css,
        [
            "color: var(--glaze-danger)",
            "color: var(--glaze-text-muted)",
            "min-width: var(--glaze-target-min)",
            "min-height: var(--glaze-target-min)",
            "var(--glaze-motion-fast)",
            "var(--glaze-state-hover)",
        ],
    )

    require_markers(
        "Primary navigation toggle accessibility",
        header,
        [
            '<button',
            'type="button"',
            'aria-label="GoreeCloud DNS navigation"',
            'aria-expanded={isMenuOpen}',
            'aria-controls="goreecloud-primary-navigation"',
            'aria-hidden="true"',
            'collapsed: !isMenuOpen',
        ],
    )

    require_markers(
        "Primary navigation landmark accessibility",
        header_menu,
        [
            '<nav id="goreecloud-primary-navigation"',
            'aria-label="GoreeCloud DNS"',
            'aria-hidden="true"',
            'focusable="false"',
        ],
    )

    require_markers(
        "Primary navigation Glaze target styling",
        header_css,
        [
            ".header-toggler",
            "min-width: var(--glaze-target-min)",
            "min-height: var(--glaze-target-min)",
            "border-radius: var(--glaze-radius-control)",
            "background: transparent",
        ],
    )

    require_markers(
        "Setup validation lifecycle",
        setup,
        [
            "useMemo",
            "SettingsFormValues",
            "const checkConfig = useMemo(",
            "debounce((values: SettingsFormValues)",
            "[dispatch]",
            "checkConfig.cancel()",
            "[checkConfig]",
        ],
    )

    require_markers(
        "Setup credential cross-field validation",
        setup_auth,
        [
            "const password = watch('password')",
            "name=\"confirm_password\"",
            "deps: ['password']",
            "confirmPassword: validateConfirmPassword",
            "<Controls isDirty={isDirty} isValid={isValid} />",
        ],
    )

    require_markers(
        "Setup progress accessibility",
        setup_progress,
        [
            "useTranslation",
            'role="progressbar"',
            "aria-label={t('install_step')}",
            "aria-valuemin={0}",
            "aria-valuemax={INSTALL_TOTAL_STEPS}",
            "aria-valuenow={step}",
            "aria-valuetext={`${step}/${INSTALL_TOTAL_STEPS}`}",
            'aria-hidden="true"',
        ],
    )

    require_markers(
        "Authentication password-help disclosure accessibility",
        login,
        [
            "const FORGOT_PASSWORD_HELP_ID = 'forgot-password-help'",
            "aria-expanded={isForgotPasswordVisible}",
            "aria-controls={FORGOT_PASSWORD_HELP_ID}",
            "id={FORGOT_PASSWORD_HELP_ID}",
        ],
    )

    require_markers(
        "Reusable input accessibility",
        input_control,
        [
            "const inputId = id ?? name",
            "htmlFor={inputId}",
            "id={inputId}",
            "aria-invalid={error ? true : undefined}",
            "aria-describedby={describedBy}",
            'role="alert"',
        ],
    )

    require_markers(
        "DNS access-form accessibility",
        dns_access_form,
        [
            "const descriptionId = `${id}-description`",
            "id={descriptionId}",
            "aria-describedby={descriptionId}",
        ],
    )

    require_markers(
        "Client modal accessibility",
        client_modal,
        [
            "aria={{ labelledby: 'client-modal-title' }}",
            'id="client-modal-title"',
        ],
    )

    for name, status_source in (("Certificate status accessibility", cert_status), ("Key status accessibility", key_status)):
        require_markers(
            name,
            status_source,
            [
                'role="status"',
                'aria-live="polite"',
            ],
        )

    require_markers(
        "DHCP interface validation accessibility",
        dhcp_interfaces,
        [
            "const interfaceErrorId = 'interface_name-error'",
            "aria-invalid={hasInterfaceError}",
            "aria-describedby={hasInterfaceError ? interfaceErrorId : undefined}",
            'role="alert"',
        ],
    )

    require_markers(
        "DHCP lease action accessibility",
        dhcp_leases,
        [
            "const leaseData = leases || []",
            "aria-label={actionLabel}",
            'aria-hidden="true"',
            'focusable="false"',
            "showPagination={leaseData.length > LEASES_TABLE_DEFAULT_PAGE_SIZE}",
        ],
    )

    require_markers(
        "DHCP IPv4 range-group accessibility",
        dhcp_v4_form,
        [
            'role="group"',
            'aria-labelledby="dhcp-v4-range-title"',
            'id="dhcp-v4-range-title"',
        ],
    )

    require_markers(
        "DHCP IPv6 range-group accessibility",
        dhcp_v6_form,
        [
            'role="group"',
            'aria-labelledby="dhcp-v6-range-title"',
            'id="dhcp-v6-range-title"',
        ],
    )

    require_markers(
        "Query Log filter accessibility",
        query_log_filter,
        [
            'role="search"',
            "aria-label={t('query_log')}",
            'id="querylog_search"',
            "aria-label={t('query_log_response_status', { value: '' })}",
            "register('response_status')",
            "clearLabel={`${t('query_log_clear')}: ${t('domain_or_client')}`}",
        ],
    )

    require_markers(
        "Query Log search-control accessibility",
        query_log_search,
        [
            "clearLabel: string",
            "'aria-describedby': ariaDescribedBy",
            "const helpId = tooltip && id ? `${id}-help` : undefined",
            "aria-describedby={describedBy}",
            'className="sr-only"',
            '<button',
            'type="button"',
            "aria-label={clearLabel}",
            "onClick={onClear}",
            'aria-hidden="true"',
            'focusable="false"',
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
            "native keyboard-operable mobile navigation button",
            "setup configuration validation debounce is memoized and canceled on teardown",
            "authentication password-help disclosure exposes its expanded state and controlled help region",
            "strict-search guidance directly associated with the search input through `aria-describedby`",
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
