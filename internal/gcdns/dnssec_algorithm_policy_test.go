package gcdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSSECSignatureAlgorithmPolicy(t *testing.T) {
	t.Parallel()

	for _, algorithm := range []uint8{5, 7, 8, 10, 13, 14, 15} {
		if !dnssecSignatureAlgorithmSupported(algorithm) {
			t.Fatalf("expected signature algorithm %d to be supported for validation", algorithm)
		}
	}

	for _, algorithm := range []uint8{1, 3, 6, 12, 16, 17, 18, 23, 253, 254} {
		if dnssecSignatureAlgorithmSupported(algorithm) {
			t.Fatalf("expected signature algorithm %d to require a separate implementation acceptance", algorithm)
		}
	}
}

func TestDNSSECDelegationPolicyRejectsSHA1Algorithms(t *testing.T) {
	t.Parallel()

	for _, algorithm := range []uint8{dnssecAlgorithmRSASHA1, dnssecAlgorithmRSASHA1NSEC3SHA1} {
		if dnssecDelegationAlgorithmAccepted(algorithm) {
			t.Fatalf("expected SHA-1 delegation algorithm %d to be rejected", algorithm)
		}
		if !dnssecSHA1DelegationAlgorithm(algorithm) {
			t.Fatalf("expected SHA-1 delegation algorithm %d to be classified explicitly", algorithm)
		}
	}
}

func TestMatchDSTreatsOnlySHA1DelegationAsInsecure(t *testing.T) {
	t.Parallel()

	validator := NewDNSSECValidator(time.Now)
	zone := "example."
	keys := []*dns.DNSKEY{{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     257,
		Protocol:  3,
		Algorithm: dnssecAlgorithmRSASHA1,
	}}

	for _, algorithm := range []uint8{dnssecAlgorithmRSASHA1, dnssecAlgorithmRSASHA1NSEC3SHA1} {
		status, err := validator.MatchDS(zone, []*dns.DS{{
			Hdr:        dns.RR_Header{Name: zone, Rrtype: dns.TypeDS, Class: dns.ClassINET},
			KeyTag:     1,
			Algorithm:  algorithm,
			DigestType: dns.SHA256,
			Digest:     "00",
		}}, keys)
		if err != nil {
			t.Fatalf("algorithm %d: unexpected error: %v", algorithm, err)
		}
		if status != DNSSECInsecure {
			t.Fatalf("algorithm %d: got %v, want %v", algorithm, status, DNSSECInsecure)
		}
	}
}

func TestMatchDSDoesNotDowngradeMixedDelegation(t *testing.T) {
	t.Parallel()

	validator := NewDNSSECValidator(time.Now)
	zone := "example."
	keys := []*dns.DNSKEY{{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     257,
		Protocol:  3,
		Algorithm: dnssecAlgorithmRSASHA256,
	}}

	status, err := validator.MatchDS(zone, []*dns.DS{
		{
			Hdr:        dns.RR_Header{Name: zone, Rrtype: dns.TypeDS, Class: dns.ClassINET},
			KeyTag:     1,
			Algorithm:  dnssecAlgorithmRSASHA1,
			DigestType: dns.SHA256,
			Digest:     "00",
		},
		{
			Hdr:        dns.RR_Header{Name: zone, Rrtype: dns.TypeDS, Class: dns.ClassINET},
			KeyTag:     2,
			Algorithm:  dnssecAlgorithmRSASHA256,
			DigestType: dns.SHA256,
			Digest:     "00",
		},
	}, keys)
	if err == nil {
		t.Fatal("expected accepted modern DS mismatch to fail rather than downgrade to insecure")
	}
	if status != DNSSECBogus {
		t.Fatalf("got %v, want %v", status, DNSSECBogus)
	}
}

func TestValidateRRSetUnsupportedAlgorithmIsIndeterminate(t *testing.T) {
	t.Parallel()

	validator := NewDNSSECValidator(time.Now)
	rrset := []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
	}}
	signatures := []*dns.RRSIG{{
		Hdr:         dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET},
		TypeCovered: dns.TypeA,
		Algorithm:   3,
		SignerName:  "example.",
	}}
	keys := []*dns.DNSKEY{{
		Hdr:       dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Protocol:  3,
		Algorithm: 3,
	}}

	status, err := validator.ValidateRRSet(rrset, signatures, keys)
	if err == nil {
		t.Fatal("expected explicit unsupported-algorithm diagnostic")
	}
	if status != DNSSECIndeterminate {
		t.Fatalf("got %v, want %v", status, DNSSECIndeterminate)
	}
}

func TestDNSSECDigestPolicy(t *testing.T) {
	t.Parallel()

	for _, digestType := range []uint8{1, 2, 4} {
		if !dnssecDSDigestSupported(digestType) {
			t.Fatalf("expected DS digest %d to be supported for validation", digestType)
		}
	}
	for _, digestType := range []uint8{0, 3, 5, 255} {
		if dnssecDSDigestSupported(digestType) {
			t.Fatalf("expected DS digest %d to remain unsupported", digestType)
		}
	}
}
