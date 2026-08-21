#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "resolver" / "README.md"
CAPABILITIES = ROOT / "resolver" / "capabilities.json"
SUBSYSTEMS = ROOT / "resolver" / "subsystems.json"
CONFIG = ROOT / "resolver" / "config.example.json"

for path in (README, CAPABILITIES, SUBSYSTEMS, CONFIG):
    if not path.is_file():
        raise SystemExit(f"resolver contract validation failed; missing {path.relative_to(ROOT)}")

contract = json.loads(CAPABILITIES.read_text(encoding="utf-8"))
subsystems = json.loads(SUBSYSTEMS.read_text(encoding="utf-8"))
config = json.loads(CONFIG.read_text(encoding="utf-8"))

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

if subsystems.get("product") != "GoreeCloud DNS":
    raise SystemExit("resolver contract validation failed; subsystem product mismatch")
if subsystems.get("production_approved") is not False:
    raise SystemExit("resolver contract validation failed; subsystem contract cannot self-approve production")
subsystem_ids = {item.get("id") for item in subsystems.get("subsystems", [])}
required_subsystems = {
    "listener", "identity-policy", "query-pipeline", "filtering", "authoritative",
    "cache", "resolver", "dhcp", "cluster", "administration", "observability",
    "configuration", "security-runtime", "extensions",
}
missing_subsystems = sorted(required_subsystems - subsystem_ids)
if missing_subsystems:
    raise SystemExit(f"resolver contract validation failed; missing subsystems: {missing_subsystems}")

owned = set()
for item in subsystems.get("subsystems", []):
    owned.update(item.get("owns", []))
platform_relationship_capabilities = {
    "public-zones", "local-zones", "local-data", "domain-blocking",
    "client-specific-policies", "centralized-multi-instance-management",
    "multi-user-administration", "dashboards", "health-monitoring",
    "runtime-statistics", "geolocation-responses", "custom-dns-processing",
}
unowned = sorted(required - owned - platform_relationship_capabilities)
if unowned:
    raise SystemExit(f"resolver contract validation failed; capabilities without subsystem ownership: {unowned}")

if config.get("production_approved") is not False:
    raise SystemExit("resolver contract validation failed; example configuration cannot self-approve production")
if config.get("security", {}).get("public_recursive_resolver") is not False:
    raise SystemExit("resolver contract validation failed; example config must not enable a public recursive resolver")
if set(config.get("security", {}).get("allow_recursion_from", [])) != {"127.0.0.0/8", "::1/128"}:
    raise SystemExit("resolver contract validation failed; example recursion ACL must remain loopback-only")
for listener_name in ("doh", "dot", "doq"):
    listener = config.get("listeners", {}).get(listener_name, {})
    if listener.get("enabled") is not False:
        raise SystemExit(f"resolver contract validation failed; {listener_name} must be disabled by default in example config")
if config.get("authoritative", {}).get("enabled") is not False:
    raise SystemExit("resolver contract validation failed; authoritative serving must be disabled by default in example config")
if config.get("dhcp", {}).get("enabled") is not False:
    raise SystemExit("resolver contract validation failed; DHCP must be disabled by default in example config")
if config.get("cluster", {}).get("enabled") is not False:
    raise SystemExit("resolver contract validation failed; clustering must be disabled by default in example config")
if config.get("extensions", {}).get("enabled") is not False:
    raise SystemExit("resolver contract validation failed; extensions must be disabled by default in example config")
if config.get("resolver", {}).get("dnssec_validation") is not True:
    raise SystemExit("resolver contract validation failed; DNSSEC validation must default on")
if config.get("filtering", {}).get("rebinding_protection") is not True:
    raise SystemExit("resolver contract validation failed; rebinding protection must default on")

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
    "Native subsystem ownership",
    "Configuration model",
    "public_recursive_resolver: false",
    "Approved Client -> GoreeCloud DNS listener",
):
    if marker not in readme:
        raise SystemExit(f"resolver contract validation failed; README missing marker: {marker}")

unbound_dir = ROOT / "resolver" / "unbound"
if unbound_dir.exists() and any(unbound_dir.iterdir()):
    raise SystemExit("resolver contract validation failed; separate Unbound backend files are prohibited")

print("GoreeCloud DNS integrated first-party DNS platform source contract: PASS")
