package gcdns

import "testing"

func TestValidateTrustAnchorDNSKEYChangeEvidenceBindsAdditionsAndRemovals(t *testing.T) {
	plan := TrustAnchorChangePlan{
		Additions: []TrustAnchorRecord{{Name: ".", KeyTag: 200, Algorithm: 15, DigestType: 2, Digest: "AA"}},
		Removals:  []TrustAnchorRecord{{Name: ".", KeyTag: 100, Algorithm: 15, DigestType: 2, Digest: "BB"}},
	}
	evidence := DNSKEYRolloverEvidence{SEPKeyTags: []uint16{200}, RevokedTags: []uint16{100}}
	if err := ValidateTrustAnchorDNSKEYChangeEvidence(plan, evidence); err != nil {
		t.Fatal(err)
	}

	missingRevoke := evidence
	missingRevoke.RevokedTags = nil
	if err := ValidateTrustAnchorDNSKEYChangeEvidence(plan, missingRevoke); err == nil {
		t.Fatal("trust-anchor removal without revoke evidence unexpectedly accepted")
	}

	missingAddition := evidence
	missingAddition.SEPKeyTags = nil
	if err := ValidateTrustAnchorDNSKEYChangeEvidence(plan, missingAddition); err == nil {
		t.Fatal("trust-anchor addition without SEP evidence unexpectedly accepted")
	}
}
