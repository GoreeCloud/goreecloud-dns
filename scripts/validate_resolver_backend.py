#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "resolver" / "README.md"
CAPABILITIES = ROOT / "resolver" / "capabilities.json"

for path in (README, CAPABILITIES):
    if not path.is_file():
        raise SystemExit(f"resolver contract validation failed; missing {path.relative_to(ROOT)}")

contract = json.loads(CAPABILITIES.read_text(encoding="utf-8"))

if contract.get("schema_version") != 2:
    raise SystemExit("resolver contract validation failed; expected schema version 2")
if contract.get("product") != "GoreeCloud DNS":
    raise SystemExit("resolver contract validation failed; wrong product authority")
if contract.get("architecture") != "single-service":
    raise SystemExit("resolver contract validation failed; architecture must be single-service")
if contract.get("runtime_authority") != "GoreeCloud/goreecloud-dns":
    raise SystemExit("resolver contract validation failed; runtime authority must be GoreeCloud DNS")
if contract.get("external_recursive_resolver_required") is not False:
    raise SystemExit("resolver contract validation failed; external recursive resolver must not be required")
if set(contract.get("target_replaces", [])) != {"AdGuard Home", "Unbound"}:
    raise SystemExit("resolver contract validation failed; target must replace AdGuard Home and Unbound")
if contract.get("production_approved") is not False:
    raise SystemExit("resolver contract validation failed; source contract cannot self-approve production")
if contract.get("runtime_acceptance_required") is not True:
    raise SystemExit("resolver contract validation failed; runtime acceptance must remain required")

required = {
    "recursive-resolution", "authoritative-dns", "internal-zones", "public-zones",
    "primary-zones", "secondary-zones", "forwarder-zones", "stub-zones",
    "catalog-zones", "zone-transfer", "zone-notify", "dnssec-validation",
    "dnssec-signing", "trust-anchor-management", "dns-cache", "persistent-cache",
    "negative-cache", "aggressive-negative-cache", "cache-ttl-controls", "serve-stale",
    "prefetch", "auto-prefetch", "concurrent-recursion",
    "latency-based-nameserver-selection", "forward-zones", "conditional-forwarding",
    "multi-upstream-failover", "encrypted-forwarding", "dns-over-https",
    "dns-over-tls", "dns-over-quic", "qname-minimization", "minimal-responses",
    "split-horizon-dns", "local-zones", "local-data", "response-policy-zones",
    "domain-blocking", "blocklists", "allowlists", "wildcard-filtering",
    "regex-filtering", "client-specific-policies", "subnet-groups",
    "advertisement-blocking", "tracker-blocking", "malware-blocking",
    "phishing-blocking", "telemetry-blocking", "dns-rebinding-protection",
    "client-access-control", "integrated-dhcp", "dhcp-dns-registration",
    "clustering", "centralized-multi-instance-management",
    "browser-administration-console", "http-api", "multi-user-administration",
    "role-based-access-control", "api-tokens", "totp-two-factor-authentication",
    "oidc-single-sign-on", "query-logging", "audit-logging", "runtime-statistics",
    "dashboards", "health-monitoring", "metrics", "runtime-administration",
    "multi-threading", "cache-sharding", "interface-restrictions",
    "query-restrictions", "privilege-separation", "resolver-hardening",
    "extensible-processing-framework", "geolocation-responses", "dns64",
    "custom-dns-processing",
}
missing = sorted(required - set(contract.get("capabilities", [])))
if missing:
    raise SystemExit(f"resolver contract validation failed; missing capabilities: {missing}")

readme = README.read_text(encoding="utf-8")
for marker in (
    "complete DNS service",
    "replaces both AdGuard Home and Unbound",
    "authoritative DNS hosting for internal and public zones",
    "DNS-over-HTTPS, DNS-over-TLS, and DNS-over-QUIC",
    "integrated DHCP server",
    "role-based access control",
    "managed cluster",
    "Extensible processing framework",
    "Approved Client -> GoreeCloud DNS listener",
):
    if marker not in readme:
        raise SystemExit(f"resolver contract validation failed; README missing marker: {marker}")

# Fail closed if the removed sidecar architecture is accidentally reintroduced.
unbound_dir = ROOT / "resolver" / "unbound"
if unbound_dir.exists() and any(unbound_dir.iterdir()):
    raise SystemExit("resolver contract validation failed; separate Unbound backend files are prohibited")

print("GoreeCloud DNS integrated first-party DNS platform source contract: PASS")
