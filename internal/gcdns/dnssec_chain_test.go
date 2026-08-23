package gcdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestTrustedKeysForDSReturnsOnlyAuthenticatedKeys(t *testing.T) {
	validator := NewDNSSECValidator(nil)
	trusted, status, err := validator.TrustedKeysForDS(".", RootTrustAnchors(), []*dns.DNSKEY{rootKSK2017()})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)
	require.Len(t, trusted, 1)
	require.EqualValues(t, 20326, trusted[0].KeyTag())
}

func TestTrustedKeysForDSRejectsMismatch(t *testing.T) {
	validator := NewDNSSECValidator(nil)
	bad := *RootTrustAnchors()[0]
	bad.Digest = "00" + bad.Digest[2:]
	trusted, status, err := validator.TrustedKeysForDS(".", []*dns.DS{&bad}, []*dns.DNSKEY{rootKSK2017()})
	require.Error(t, err)
	require.Equal(t, DNSSECBogus, status)
	require.Empty(t, trusted)
}

func TestAuthenticateDNSKEYResponseRequiresSignedRRSet(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{rootKSK2017()}
	validator := NewDNSSECValidator(nil)
	keys, status, err := validator.AuthenticateDNSKEYResponse(".", msg, RootTrustAnchors())
	require.Error(t, err)
	require.Equal(t, DNSSECBogus, status)
	require.Empty(t, keys)
}

func TestAuthenticateDelegationDSRequiresParentSignature(t *testing.T) {
	childKey := rootKSK2017()
	childKey.Hdr.Name = "example.test."
	ds := childKey.ToDS(dns.SHA256)
	require.NotNil(t, ds)
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{ds}
	validator := NewDNSSECValidator(nil)
	records, status, err := validator.AuthenticateDelegationDS("example.test.", msg, []*dns.DNSKEY{rootKSK2017()})
	require.Error(t, err)
	require.Equal(t, DNSSECBogus, status)
	require.Empty(t, records)
}

func TestAuthenticateDelegationDSMissingDSRemainsIndeterminate(t *testing.T) {
	validator := NewDNSSECValidator(nil)
	records, status, err := validator.AuthenticateDelegationDS("unsigned.test.", new(dns.Msg), []*dns.DNSKEY{rootKSK2017()})
	require.NoError(t, err)
	require.Equal(t, DNSSECIndeterminate, status)
	require.Empty(t, records)
}

func TestAuthenticateDelegationDSAcceptsNSEC3InsecureProof(t *testing.T) {
	zone := "example.test."
	child := "unsigned.example.test."
	key, signer := nsec3TestKey(t, zone)
	record := nsec3TestRecord(child, zone, []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC3})
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{record, signNSEC3TestRecord(t, record, key, signer)}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	records, status, err := validator.AuthenticateDelegationDS(child, msg, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECInsecure, status)
	require.Empty(t, records)
}

func TestAuthenticateDelegationDSAcceptsNSEC3OptOutInsecureProof(t *testing.T) {
	zone := "example.test."
	child := "unsigned.example.test."
	key, signer := nsec3TestKey(t, zone)
	proof := nsec3TestRecord(zone, zone, []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC3})
	proof.Flags = nsec3OptOutFlag
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{
		nsec3TestDelegationNS(child),
		proof,
		signNSEC3TestRecord(t, proof, key, signer),
	}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	records, status, err := validator.AuthenticateDelegationDS(child, msg, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECInsecure, status)
	require.Empty(t, records)
}

func TestAuthenticateDelegationDSNSEC3OptOutMissingReferralRemainsIndeterminate(t *testing.T) {
	zone := "example.test."
	child := "unsigned.example.test."
	key, signer := nsec3TestKey(t, zone)
	proof := nsec3TestRecord(zone, zone, []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC3})
	proof.Flags = nsec3OptOutFlag
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{proof, signNSEC3TestRecord(t, proof, key, signer)}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	records, status, err := validator.AuthenticateDelegationDS(child, msg, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECIndeterminate, status)
	require.Empty(t, records)
}

func TestAuthenticateDelegationDSNSEC3OptOutFailsClosed(t *testing.T) {
	zone := "example.test."
	child := "unsigned.example.test."
	key, _ := nsec3TestKey(t, zone)
	proof := nsec3TestRecord(zone, zone, []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC3})
	proof.Flags = nsec3OptOutFlag
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{nsec3TestDelegationNS(child), proof}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	records, status, err := validator.AuthenticateDelegationDS(child, msg, []*dns.DNSKEY{key})
	require.Error(t, err)
	require.Equal(t, DNSSECBogus, status)
	require.Empty(t, records)
}

func TestDNSKEYMaterialFiltersZoneAndType(t *testing.T) {
	key := rootKSK2017()
	other := *key
	other.Hdr.Name = "other."
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET}, TypeCovered: dns.TypeDNSKEY}
	wrongSig := &dns.RRSIG{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET}, TypeCovered: dns.TypeA}
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{key, &other, sig, wrongSig}
	keys, sigs := dnskeyMaterial(msg, ".")
	require.Len(t, keys, 1)
	require.Len(t, sigs, 1)
}
