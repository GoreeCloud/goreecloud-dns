#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IDENTITY = ROOT / 'client' / 'src' / 'productIdentity.ts'
ICON = ROOT / 'client' / 'public' / 'assets' / 'goreecloud-dns-mark.svg'
ENTRYPOINTS = (
    ROOT / 'client' / 'src' / 'index.tsx',
    ROOT / 'client' / 'src' / 'install' / 'index.tsx',
    ROOT / 'client' / 'src' / 'login' / 'index.tsx',
)
HTML_SHELLS = (
    ROOT / 'client' / 'public' / 'index.html',
    ROOT / 'client' / 'public' / 'install.html',
    ROOT / 'client' / 'public' / 'login.html',
)

required_identity_markers = (
    "const UPSTREAM_PRODUCT_NAME = 'AdGuard Home';",
    "const GOREECLOUD_PRODUCT_NAME = 'GoreeCloud DNS';",
    'value.split(UPSTREAM_PRODUCT_NAME).join(GOREECLOUD_PRODUCT_NAME)',
    "i18n.getResourceBundle(language, 'translation')",
    "i18n.addResourceBundle(language, 'translation'",
)

identity_text = IDENTITY.read_text(encoding='utf-8')

missing = [marker for marker in required_identity_markers if marker not in identity_text]
if missing:
    raise SystemExit(f'product identity validation failed; missing markers: {missing}')

for entrypoint in ENTRYPOINTS:
    entrypoint_text = entrypoint.read_text(encoding='utf-8')
    if 'productIdentity' not in entrypoint_text:
        relative = entrypoint.relative_to(ROOT)
        raise SystemExit(
            f'product identity validation failed; {relative} does not load productIdentity'
        )

if not ICON.is_file():
    raise SystemExit('product identity validation failed; native GoreeCloud DNS mark is missing')

icon_text = ICON.read_text(encoding='utf-8')
for marker in ('GoreeCloud DNS', 'shield containing a cloud', '#287d68'):
    if marker not in icon_text:
        raise SystemExit(
            f'product identity validation failed; DNS mark missing required marker: {marker}'
        )

for shell in HTML_SHELLS:
    shell_text = shell.read_text(encoding='utf-8')
    relative = shell.relative_to(ROOT)
    required_shell_markers = (
        'assets/goreecloud-dns-mark.svg',
        'name="theme-color" content="#287d68"',
        'GoreeCloud DNS',
    )
    missing_shell_markers = [
        marker for marker in required_shell_markers if marker not in shell_text
    ]
    if missing_shell_markers:
        raise SystemExit(
            'product identity validation failed; '
            f'{relative} missing markers: {missing_shell_markers}'
        )

if "split('AdGuard')" in identity_text or "replace('AdGuard'" in identity_text:
    raise SystemExit('product identity validation failed; generic AdGuard replacement is prohibited')

if 'AdGuardTeam' in identity_text:
    raise SystemExit('product identity validation failed; upstream organization references must not be rewritten here')

print('GoreeCloud DNS product identity source contract: PASS')
