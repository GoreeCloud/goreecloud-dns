#!/usr/bin/env python3
"""Fail-closed source contract for Beacon persistent trust-anchor lifecycle state."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "internal/gcdns/trust_anchor_state.go"
TESTS = ROOT / "internal/gcdns/trust_anchor_state_test.go"
DOCS = ROOT / "docs/trust-anchor-lifecycle.md"
WORKFLOW = ROOT / ".github/workflows/lint.yml"


def require(path: Path, markers: list[str]) -> None:
    if not path.is_file():
        raise SystemExit(f"missing required file: {path.relative_to(ROOT)}")
    text = path.read_text(encoding="utf-8")
    missing = [marker for marker in markers if marker not in text]
    if missing:
        raise SystemExit(
            f"{path.relative_to(ROOT)} missing required trust-anchor lifecycle markers: {missing}"
        )


def main() -> None:
    require(
        SOURCE,
        [
            "goreecloud-beacon-trust-anchor-state/v1",
            "BootstrapTrustAnchorState",
            "type TrustAnchorStore struct",
            "func (s *TrustAnchorStore) Load()",
            "func (s *TrustAnchorStore) Save(",
            "func (s *TrustAnchorStore) StageUpdate(",
            "func (s *TrustAnchorStore) ApprovePending(",
            "func (s *TrustAnchorStore) RejectPending(",
            "os.CreateTemp",
            "tmp.Chmod(0o600)",
            "os.Rename(tmpName, s.path)",
            "trustAnchorFingerprint",
            "only root DS trust anchors are supported",
        ],
    )
    require(
        TESTS,
        [
            "TestBootstrapTrustAnchorState",
            "TestTrustAnchorStoreRoundTripAndPermissions",
            "TestTrustAnchorUpdateRequiresExplicitFingerprintApproval",
            "TestTrustAnchorUpdateCanBeRejectedWithoutChangingActiveSet",
            "TestTrustAnchorStoreRejectsUnchangedUpdate",
            "TestTrustAnchorStateRejectsUnapprovedAlgorithmsAndNonRootNames",
            "TestTrustAnchorPendingFingerprintIsTamperEvident",
        ],
    )
    require(
        DOCS,
        [
            "# Beacon Trust-Anchor Lifecycle",
            "at most one pending proposed replacement set",
            "Explicit approval",
            "RFC 5011",
            "No production DNS service reads this state yet.",
        ],
    )
    require(WORKFLOW, ["scripts/validate_trust_anchor_lifecycle.py"])
    print("Beacon persistent trust-anchor lifecycle source contract: PASS")


if __name__ == "__main__":
    main()
