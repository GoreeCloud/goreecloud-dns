#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UNBOUND = ROOT / "resolver" / "unbound" / "unbound.conf"
LOCAL_ZONES = ROOT / "resolver" / "unbound" / "local-zones.conf"
RPZ = ROOT / "resolver" / "unbound" / "rpz.conf"
README = ROOT / "resolver" / "README.md"

for path in (UNBOUND, LOCAL_ZONES, RPZ, README):
    if not path.is_file():
        raise SystemExit(f"resolver backend validation failed; missing {path.relative_to(ROOT)}")

text = UNBOUND.read_text(encoding="utf-8")
required = (
    'interface: 127.0.0.1@5353',
    'access-control: 0.0.0.0/0 refuse',
    'auto-trust-anchor-file:',
    'aggressive-nsec: yes',
    'serve-expired: yes',
    'prefetch: yes',
    'qname-minimisation: yes',
    'minimal-responses: yes',
    'cache-min-ttl:',
    'cache-max-ttl:',
    'cache-max-negative-ttl:',
    'num-threads:',
    'msg-cache-slabs:',
    'rrset-cache-slabs:',
    'private-address: 10.0.0.0/8',
    'control-enable: yes',
    'control-interface: 127.0.0.1',
    'extended-statistics: yes',
    'forward-zone:',
)
missing = [marker for marker in required if marker not in text]
if missing:
    raise SystemExit(f"resolver backend validation failed; missing markers: {missing}")

# Fail closed against accidental broad exposure or permissive validation.
prohibited = (
    'interface: 0.0.0.0',
    'interface: ::0',
    'access-control: 0.0.0.0/0 allow',
    'access-control: ::0/0 allow',
    'val-permissive-mode: yes',
    'control-use-cert: no',
)
present = [marker for marker in prohibited if marker in text]
if present:
    raise SystemExit(f"resolver backend validation failed; prohibited markers: {present}")

# Cache slab counts must be powers of two and no smaller than one.
for key in ('msg-cache-slabs', 'rrset-cache-slabs', 'infra-cache-slabs', 'key-cache-slabs'):
    line = next(line for line in text.splitlines() if line.strip().startswith(f'{key}:'))
    value = int(line.split(':', 1)[1].strip())
    if value < 1 or value & (value - 1):
        raise SystemExit(f"resolver backend validation failed; {key} must be a power of two")

print("GoreeCloud DNS resolver backend source contract: PASS")
