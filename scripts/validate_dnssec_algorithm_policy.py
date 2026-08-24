#!/usr/bin/env python3
"""Fail-closed source contract for Beacon DNSSEC algorithm and digest policy."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "internal/gcdns/dnssec_algorithm_policy.go"
VALIDATOR = ROOT / "internal/gcdns/dnssec.go"
TESTS = ROOT / "internal/gcdns/dnssec_algorithm_policy_test.go"
DOCS = ROOT / "docs/beacon.md"
WORKFLOW = ROOT / ".github/workflows/lint.yml"


def require(path: Path, markers: list[str]) -> None:
    if not path.is_file():
        raise SystemExit(f"missing required file: {path.relative_to(ROOT)}")
    text = path.read_text(encoding="utf-8")
    missing = [marker for marker in markers if marker not in text]
    if missing:
        raise SystemExit(
            f"{path.relative_to(ROOT)} missing required DNSSEC algorithm-policy markers: {missing}"
        )


def main() -> None:
    require(
        POLICY,
        [
            "dnssecSignatureAlgorithmSupported",
            "dnssecDelegationAlgorithmAccepted",
            "dnssecSHA1DelegationAlgorithm",
            "dnssecDSDigestSupported",
            "dnssecAlgorithmRSASHA1",
            "dnssecAlgorithmRSASHA1NSEC3SHA1",
            "dnssecAlgorithmRSASHA256",
            "dnssecAlgorithmRSASHA512",
            "dnssecAlgorithmECDSAP256SHA256",
            "dnssecAlgorithmECDSAP384SHA384",
            "dnssecAlgorithmED25519",
        ],
    )
    require(
        VALIDATOR,
        [
            "dnssecDSDigestSupported(ds.DigestType)",
            "dnssecSHA1DelegationAlgorithm(ds.Algorithm)",
            "dnssecDelegationAlgorithmAccepted(ds.Algorithm)",
            "return DNSSECInsecure, nil",
            "dnssecSignatureAlgorithmSupported(sig.Algorithm)",
            "DNSSEC RRset has no supported signature algorithm",
        ],
    )
    require(
        TESTS,
        [
            "TestDNSSECSignatureAlgorithmPolicy",
            "TestDNSSECDelegationPolicyRejectsSHA1Algorithms",
            "TestMatchDSTreatsOnlySHA1DelegationAsInsecure",
            "TestMatchDSDoesNotDowngradeMixedDelegation",
            "TestValidateRRSetUnsupportedAlgorithmIsIndeterminate",
            "TestDNSSECDigestPolicy",
        ],
    )
    require(
        DOCS,
        [
            "### DNSSEC algorithm and digest policy",
            "DNSSEC key-size policy is still a separate unfinished part of this milestone.",
        ],
    )
    require(WORKFLOW, ["scripts/validate_dnssec_algorithm_policy.py"])
    print("Beacon DNSSEC algorithm/digest policy source contract: PASS")


if __name__ == "__main__":
    main()
