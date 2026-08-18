#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IDENTITY = ROOT / 'client' / 'src' / 'productIdentity.ts'
INDEX = ROOT / 'client' / 'src' / 'index.tsx'

required_identity_markers = (
    "const UPSTREAM_PRODUCT_NAME = 'AdGuard Home';",
    "const GOREECLOUD_PRODUCT_NAME = 'GoreeCloud DNS';",
    'value.split(UPSTREAM_PRODUCT_NAME).join(GOREECLOUD_PRODUCT_NAME)',
    "i18n.getResourceBundle(language, 'translation')",
    "i18n.addResourceBundle(language, 'translation'",
)

identity_text = IDENTITY.read_text(encoding='utf-8')
index_text = INDEX.read_text(encoding='utf-8')

missing = [marker for marker in required_identity_markers if marker not in identity_text]
if missing:
    raise SystemExit(f'product identity validation failed; missing markers: {missing}')

if "import './productIdentity';" not in index_text:
    raise SystemExit('product identity validation failed; application entrypoint does not load productIdentity')

if "split('AdGuard')" in identity_text or "replace('AdGuard'" in identity_text:
    raise SystemExit('product identity validation failed; generic AdGuard replacement is prohibited')

if 'AdGuardTeam' in identity_text:
    raise SystemExit('product identity validation failed; upstream organization references must not be rewritten here')

print('GoreeCloud DNS product identity source contract: PASS')
