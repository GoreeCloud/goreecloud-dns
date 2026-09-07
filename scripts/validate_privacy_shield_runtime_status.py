#!/usr/bin/env python3
"""Fail-closed source validation for GoreeCloud DNS Privacy Shield runtime status."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "privacy-shield" / "status-contract.lock.json"
ADAPTER = ROOT / "privacy-shield" / "adapter.json"
STATUS = ROOT / "goreecloud" / "privacyshieldstatus" / "status.go"
STATUS_TEST = ROOT / "goreecloud" / "privacyshieldstatus" / "status_test.go"
WRITE = ROOT / "goreecloud" / "privacyshieldstatus" / "write.go"
WRITE_TEST = ROOT / "goreecloud" / "privacyshieldstatus" / "write_test.go"
HOME = ROOT / "internal" / "home" / "goreecloudstatus.go"
DOC = ROOT / "docs" / "privacy-shield-runtime-status.md"

EXPECTED_LOCK = {
    "source_repository": "GoreeCloud/goreecloud-privacy-shield",
    "source_revision": "f10d90c0c53c0b876d6ff5cdb6926d6b87205438",
    "adapter_schema_blob": "cc0a50a3d0d5151d06ed34be2df30266a91c3bf9",
    "capabilities_blob": "d9bb4e26cf7eb3b90034f763e885d47023df3664",
    "status_schema_blob": "f6b62576e68e19ad8b25ced5383f8a3df74716fb",
}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def read(path: Path) -> str:
    if not path.is_file():
        fail(f"missing required file: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def require(name: str, text: str, markers: tuple[str, ...]) -> None:
    missing = [marker for marker in markers if marker not in text]
    if missing:
        fail(f"{name} missing markers: {', '.join(missing)}")


def main() -> None:
    try:
        lock = json.loads(read(LOCK))
        adapter = json.loads(read(ADAPTER))
    except json.JSONDecodeError as exc:
        fail(f"invalid Privacy Shield JSON: {exc}")

    if lock.get("schema_version") != 1:
        fail("Privacy Shield status contract lock schema must remain 1")
    if lock.get("source_repository") != EXPECTED_LOCK["source_repository"]:
        fail("Privacy Shield source repository drifted")
    if lock.get("source_revision") != EXPECTED_LOCK["source_revision"]:
        fail("reviewed Privacy Shield source revision drifted without fresh validation update")
    if lock.get("adapter_schema", {}).get("blob") != EXPECTED_LOCK["adapter_schema_blob"]:
        fail("reviewed Privacy Shield adapter schema blob drifted")
    if lock.get("capabilities_registry", {}).get("blob") != EXPECTED_LOCK["capabilities_blob"]:
        fail("reviewed Privacy Shield capability registry blob drifted")
    if lock.get("status_schema", {}).get("blob") != EXPECTED_LOCK["status_schema_blob"]:
        fail("reviewed Privacy Shield status schema blob drifted")

    if adapter.get("capabilities") != ["dns-privacy"]:
        fail("runtime status branch must retain the DNS-only Privacy Shield adapter scope")
    acceptance = adapter.get("acceptance", {})
    if acceptance.get("runtime_acceptance_required") is not True or acceptance.get("production_approved") is not False:
        fail("Privacy Shield adapter must remain runtime-acceptance gated and unapproved")

    status = read(STATUS)
    require(
        "privacyshieldstatus/status.go",
        status,
        (
            'SchemaVersion = 1',
            'json:"adapter_id"',
            'json:"product"',
            'json:"runtime_authority"',
            'json:"adapter_contract_version"',
            'json:"generated_at"',
            'json:"valid_until,omitempty"',
            'json:"state"',
            'json:"capabilities"',
            'json:"raw_private_activity_included"',
            'json:"contains_credentials"',
            'json:"contains_identifiers"',
            'json:"runtime_acceptance_required"',
            'json:"production_approved"',
            'AdapterID:              "dns"',
            'Product:                "GoreeCloud DNS"',
            'RuntimeAuthority:       "GoreeCloud/goreecloud-dns"',
            'AdapterContractVersion: 1',
            'state := "development"',
            'capabilityState := "pending-acceptance"',
            'state = "unavailable"',
            'capabilityState = "unavailable"',
            'state = "attention"',
            'capabilityState = "inactive"',
            'ID: "dns-privacy"',
            'RuntimeAcceptanceRequired: true',
            'ProductionApproved:        false',
        ),
    )

    for forbidden_tag in (
        'json:"query_name"',
        'json:"client_identifier"',
        'json:"source_address"',
        'json:"credential"',
        'json:"private_key"',
        'json:"certificate_material"',
        'json:"filter_content"',
    ):
        if forbidden_tag in status:
            fail(f"Privacy Shield status exposes forbidden serialized field {forbidden_tag}")

    status_test = read(STATUS_TEST)
    require(
        "privacyshieldstatus/status_test.go",
        status_test,
        (
            "TestReadyEvidenceRemainsPendingAcceptance",
            "TestResolverUnavailableFailsClosed",
            "TestPrivacyCapabilityInactiveWhenFilteringOrPolicyUnavailable",
            "TestSerializedStatusIsPrivacyMinimized",
            'snapshot.ValidUntil != ""',
        ),
    )

    write = read(WRITE)
    require(
        "privacyshieldstatus/write.go",
        write,
        (
            "os.CreateTemp",
            ".goreecloud-dns-privacy-status-*",
            "file.Chmod(0o600)",
            "file.Sync()",
            "os.Rename(tmp, path)",
        ),
    )
    require(
        "privacyshieldstatus/write_test.go",
        read(WRITE_TEST),
        (
            "TestWriteFileAtomicallyWritesSeparatePrivacyStatus",
            'runtime.GOOS != "windows"',
            "TestWriteFileRejectsEmptyPath",
        ),
    )

    home = read(HOME)
    require(
        "internal/home/goreecloudstatus.go",
        home,
        (
            'GOREECLOUD_DNS_STATUS_FILE',
            'GOREECLOUD_DNS_PRIVACY_SHIELD_STATUS_FILE',
            "privacyshieldstatus.SnapshotFromEvidence(now, evidence)",
            "privacyshieldstatus.WriteFile(privacyShieldPath, snapshot)",
            "goreecloudstatus.SnapshotFromEvidence(now, evidence)",
        ),
    )

    doc = read(DOC).lower()
    for phrase in (
        "development-only privacy shield runtime-status projection",
        "privacy shield status and goreecloud infrastructure status are separate governed contracts",
        "goreecloud_dns_privacy_shield_status_file",
        "production_approved: false",
        "no raw private activity",
        "no credentials",
        "no identifiers",
        "has no path to top-level `protected`",
        "no production cutover or stable classification is authorized",
    ):
        if phrase not in doc:
            fail(f"Privacy Shield runtime-status documentation missing boundary: {phrase}")

    print("GoreeCloud DNS Privacy Shield runtime-status validation passed.")


if __name__ == "__main__":
    main()
