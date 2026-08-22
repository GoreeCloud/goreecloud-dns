package gcdns

import (
	"testing"

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
