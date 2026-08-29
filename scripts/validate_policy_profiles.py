#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

required = {
    "internal/gcdns/policy_profiles.go": (
        "type PolicyProfileEngine struct",
        "func NewPolicyProfileEngine",
        "PolicyActionAllow",
        "PolicyActionBlock",
        "PolicyActionRewrite",
        "PolicyMatchExact",
        "PolicyMatchSuffix",
        "PolicyMatchCategory",
        "PolicyMatchService",
        "left.prefix.Bits() > right.prefix.Bits()",
        "duplicate normalized catalog entry",
        "DNSSECStatus: DNSSECIndeterminate",
        "AssignmentScope",
        "RecordPolicyDecision",
        "buildPolicyRewriteResponse",
        "var _ Policy = (*PolicyProfileEngine)(nil)",
    ),
    "internal/gcdns/policy_profiles_test.go": (
        "TestPolicyProfileEngineClientAssignmentOverridesNetworkAndDefault",
        "TestPolicyProfileEngineLongestNetworkPrefixWins",
        "TestPolicyProfileEnginePriorityAllowsCustomExceptionOverServiceBlock",
        "TestPolicyProfileEngineEqualPriorityUsesExactBeforeSuffix",
        "TestPolicyProfileEngineScheduledRule",
        "TestPolicyProfileEngineOvernightScheduleUsesPreviousDay",
        "TestPolicyProfileEngineBlockNXDOMAIN",
        "TestPolicyProfileEngineAddressRewrite",
        "TestPolicyProfileEngineCNAMERewrite",
        "TestPolicyDecisionIsPrivacyMinimized",
        "TestPolicyProfileEngineRejectsConflictingAssignments",
    ),
    "internal/gcdns/policy_profiles_hardening_test.go": (
        "TestPolicyProfileEngineTrimsProfileReferences",
        "TestPolicyProfileEngineRejectsNormalizedCatalogCollision",
        "TestPolicyProfileEngineSyntheticResultIsDNSSECIndeterminate",
    ),
    "docs/policy-profiles.md": (
        "Beacon Policy Profiles",
        "Assignment precedence",
        "Rule precedence",
        "Schedules",
        "Categories and services",
        "Privacy-safe decision trace",
        "Production boundary",
        "NextDNS",
        "Control D",
    ),
    "docs/competitive-superset-requirement.md": (
        "NextDNS",
        "Control D",
        "reusable profiles",
        "service/application controls",
        "privacy-aware analytics",
    ),
}

for rel, markers in required.items():
    path = ROOT / rel
    if not path.is_file():
        raise SystemExit(f"Beacon policy-profile validation failed: missing {rel}")
    text = path.read_text(encoding="utf-8")
    for marker in markers:
        if marker not in text:
            raise SystemExit(f"Beacon policy-profile validation failed: {rel} missing {marker!r}")

print("GoreeCloud Beacon policy profiles, assignments, schedules, categories/services, rewrites, normalization hardening, and privacy-safe decision contract: PASS")
