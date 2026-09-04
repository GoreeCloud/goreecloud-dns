package gcdns

import "errors"

// ValidateTrustAnchorDNSKEYChangeEvidence binds a DS-level change plan to an
// authenticated DNSKEY observation. Every added trust-anchor key tag must be
// present as a SEP key and every removed key tag must be present in RFC 5011
// revoke evidence normalized to its pre-revoke identity.
func ValidateTrustAnchorDNSKEYChangeEvidence(plan TrustAnchorChangePlan, evidence DNSKEYRolloverEvidence) error {
	sep := make(map[uint16]struct{}, len(evidence.SEPKeyTags))
	for _, tag := range evidence.SEPKeyTags {
		sep[tag] = struct{}{}
	}
	revoked := make(map[uint16]struct{}, len(evidence.RevokedTags))
	for _, tag := range evidence.RevokedTags {
		revoked[tag] = struct{}{}
	}
	for _, addition := range plan.Additions {
		if _, ok := sep[addition.KeyTag]; !ok {
			return errors.New("goreecloud dns: trust-anchor addition is not present in authenticated SEP DNSKEY evidence")
		}
	}
	for _, removal := range plan.Removals {
		if _, ok := revoked[removal.KeyTag]; !ok {
			return errors.New("goreecloud dns: trust-anchor removal lacks authenticated RFC 5011 revoke evidence")
		}
	}
	return nil
}
