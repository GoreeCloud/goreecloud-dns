package gcdns

// DNSSEC algorithm policy is intentionally explicit instead of treating every
// algorithm understood by a crypto library as automatically acceptable.
//
// RFC 9904 moved the canonical implementation/use recommendations to the IANA
// DNSSEC registries.  RFC 9905 additionally requires validating resolvers to
// treat RSASHA1 and RSASHA1-NSEC3-SHA1 DS delegations as insecure while still
// supporting validation of legacy RRSIG/DNSKEY data using those algorithms.
//
// Beacon currently enables the algorithms implemented by the underlying Go
// DNS library that also have an IANA validation recommendation.  Ed448 and
// newer MAY algorithms remain unsupported until their cryptographic
// implementation and deterministic test coverage are explicitly accepted.

const (
	dnssecAlgorithmRSASHA1          uint8 = 5
	dnssecAlgorithmRSASHA1NSEC3SHA1 uint8 = 7
	dnssecAlgorithmRSASHA256        uint8 = 8
	dnssecAlgorithmRSASHA512        uint8 = 10
	dnssecAlgorithmECDSAP256SHA256  uint8 = 13
	dnssecAlgorithmECDSAP384SHA384  uint8 = 14
	dnssecAlgorithmED25519          uint8 = 15
)

func dnssecSignatureAlgorithmSupported(algorithm uint8) bool {
	switch algorithm {
	case dnssecAlgorithmRSASHA1,
		dnssecAlgorithmRSASHA1NSEC3SHA1,
		dnssecAlgorithmRSASHA256,
		dnssecAlgorithmRSASHA512,
		dnssecAlgorithmECDSAP256SHA256,
		dnssecAlgorithmECDSAP384SHA384,
		dnssecAlgorithmED25519:
		return true
	default:
		return false
	}
}

func dnssecDelegationAlgorithmAccepted(algorithm uint8) bool {
	// RFC 9905: SHA-1 DNSSEC signing algorithms MUST NOT be used to create DS
	// records and validators MUST treat those delegations as insecure.
	if dnssecSHA1DelegationAlgorithm(algorithm) {
		return false
	}

	switch algorithm {
	case dnssecAlgorithmRSASHA256,
		dnssecAlgorithmRSASHA512,
		dnssecAlgorithmECDSAP256SHA256,
		dnssecAlgorithmECDSAP384SHA384,
		dnssecAlgorithmED25519:
		return true
	default:
		return false
	}
}

func dnssecSHA1DelegationAlgorithm(algorithm uint8) bool {
	return algorithm == dnssecAlgorithmRSASHA1 || algorithm == dnssecAlgorithmRSASHA1NSEC3SHA1
}

func dnssecDSDigestSupported(digestType uint8) bool {
	// SHA-1 remains required/recommended for validation even though new
	// SHA-1-based delegations are prohibited by RFC 9905.  SHA-256 and
	// SHA-384 are the preferred modern DS digest families supported here.
	return digestType == 1 || digestType == 2 || digestType == 4
}
