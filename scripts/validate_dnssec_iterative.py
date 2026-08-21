#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = {
    "iterative DNSSEC resolver": ROOT / "internal" / "gcdns" / "iterative_dnssec.go",
    "iterative DNSSEC tests": ROOT / "internal" / "gcdns" / "iterative_dnssec_test.go",
    "root trust anchors": ROOT / "internal" / "gcdns" / "root_trust_anchors.go",
    "DNSSEC chain": ROOT / "internal" / "gcdns" / "dnssec_chain.go",
    "iterative resolver": ROOT / "internal" / "gcdns" / "iterative_resolver.go",
    "integrated resolver validator": ROOT / "scripts" / "validate_resolver_backend.py",
}

for label, path in FILES.items():
    if not path.is_file():
        raise SystemExit(f"dnssec iterative validation failed; missing {label}: {path.relative_to(ROOT)}")

resolver = FILES["iterative DNSSEC resolver"].read_text(encoding="utf-8")
for marker in (
    "type DNSSECIterativeResolver struct",
    "func NewDNSSECIterativeResolver",
    "ValidateRootDNSKEY",
    "ValidateSignedDelegation",
    "validateTerminalPositive",
    "authenticated denial with NSEC/NSEC3 is required",
    "out.DNSSECStatus = status",
    "ensureDNSSECOK(query)",
):
    if marker not in resolver:
        raise SystemExit(f"dnssec iterative validation failed; resolver missing marker: {marker}")

tests = FILES["iterative DNSSEC tests"].read_text(encoding="utf-8")
for marker in (
    "TestDNSSECIterativeResolverCarriesAuthenticatedKeysAcrossReferral",
    "TestDNSSECIterativeResolverFailsClosedOnNegativeWithoutDenialProof",
    "TestDNSSECIterativeResolverRequiresTrustInputs",
):
    if marker not in tests:
        raise SystemExit(f"dnssec iterative validation failed; test missing marker: {marker}")

anchors = FILES["root trust anchors"].read_text(encoding="utf-8")
for marker in (
    "20326",
    "38696",
    "rootKSK2017Digest",
    "rootKSK2024Digest",
    "ValidateRootDNSKEY",
):
    if marker not in anchors:
        raise SystemExit(f"dnssec iterative validation failed; trust-anchor source missing marker: {marker}")

chain = FILES["DNSSEC chain"].read_text(encoding="utf-8")
for marker in (
    "ValidateSignedDelegation",
    "authenticated denial is required",
    "delegationDSMaterial",
    "dnskeyMaterial",
    "matchingDSKeys",
):
    if marker not in chain:
        raise SystemExit(f"dnssec iterative validation failed; chain source missing marker: {marker}")

classic = FILES["iterative resolver"].read_text(encoding="utf-8")
if "ensureDNSSECOK(query)" not in classic:
    raise SystemExit("dnssec iterative validation failed; classic iterative queries do not request DNSSEC material")

integrated = FILES["integrated resolver validator"].read_text(encoding="utf-8")
for marker in (
    'ROOT / "internal" / "gcdns" / "iterative_dnssec.go"',
    'ROOT / "internal" / "gcdns" / "iterative_dnssec_test.go"',
    'ROOT / "internal" / "gcdns" / "root_trust_anchors.go"',
    'ROOT / "internal" / "gcdns" / "dnssec_chain.go"',
    '"type DNSSECIterativeResolver struct"',
    '"authenticated denial with NSEC/NSEC3 is required"',
):
    if marker not in integrated:
        raise SystemExit(f"dnssec iterative validation failed; integrated resolver validator missing marker: {marker}")

print("GoreeCloud DNS Beacon iterative DNSSEC source contract: PASS")
