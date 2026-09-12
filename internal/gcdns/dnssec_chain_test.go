package gcdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestValidateSignedDelegationRequiresAuthenticatedDenialForMissingDS(t *testing.T) {
	validator := NewDNSSECValidator(nil)
	parent := []*dns.DNSKEY{{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: "AwEAAQ==",
	}}

	status, keys, err := validator.ValidateSignedDelegation(parent, new(dns.Msg), new(dns.Msg), "example.")
	require.ErrorContains(t, err, "authenticated denial")
	require.Equal(t, DNSSECIndeterminate, status)
	require.Nil(t, keys)
}

func TestDelegationDSMaterialSeparatesDSAndSignatures(t *testing.T) {
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns.example."},
		&dns.DS{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeDS, Class: dns.ClassINET}, KeyTag: 1234, Algorithm: dns.RSASHA256, DigestType: dns.SHA256, Digest: "AA"},
		&dns.RRSIG{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET}, TypeCovered: dns.TypeDS},
	}

	rrset, records, signatures := delegationDSMaterial(msg, "example.")
	require.Len(t, rrset, 1)
	require.Len(t, records, 1)
	require.Len(t, signatures, 1)
}

func TestDNSKEYMaterialRejectsOtherZones(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.DNSKEY{Hdr: dns.RR_Header{Name: "other.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET}, Flags: 257, Protocol: 3, Algorithm: dns.RSASHA256, PublicKey: "AwEAAQ=="},
		&dns.RRSIG{Hdr: dns.RR_Header{Name: "other.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET}, TypeCovered: dns.TypeDNSKEY},
	}

	rrset, keys, signatures := dnskeyMaterial(msg, "example.")
	require.Empty(t, rrset)
	require.Empty(t, keys)
	require.Empty(t, signatures)
}

func TestSameDigestIsCaseInsensitive(t *testing.T) {
	require.True(t, sameDigest("ABCDEF0123", "abcdef0123"))
	require.False(t, sameDigest("ABCDEF0123", "abcdef0124"))
}
