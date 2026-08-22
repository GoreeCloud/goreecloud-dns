package gcdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func rootKSK2017() *dns.DNSKEY {
	return &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 172800},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
	}
}

func TestRootTrustAnchors(t *testing.T) {
	anchors := RootTrustAnchors()
	require.Len(t, anchors, 2)
	require.EqualValues(t, 20326, anchors[0].KeyTag)
	require.Equal(t, "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D", anchors[0].Digest)
	require.EqualValues(t, 38696, anchors[1].KeyTag)
	require.Equal(t, "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16", anchors[1].Digest)
}

func TestDNSSECValidatorMatchesRootKSK2017(t *testing.T) {
	validator := NewDNSSECValidator(nil)
	status, err := validator.MatchDS(".", RootTrustAnchors(), []*dns.DNSKEY{rootKSK2017()})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)
}

func TestDNSSECValidatorRejectsDSMismatch(t *testing.T) {
	anchors := RootTrustAnchors()
	bad := *anchors[0]
	bad.Digest = "00" + bad.Digest[2:]
	validator := NewDNSSECValidator(nil)
	status, err := validator.MatchDS(".", []*dns.DS{&bad}, []*dns.DNSKEY{rootKSK2017()})
	require.Error(t, err)
	require.Equal(t, DNSSECBogus, status)
}

func TestDNSSECValidatorNoDSIsIndeterminate(t *testing.T) {
	validator := NewDNSSECValidator(nil)
	status, err := validator.MatchDS("unsigned.test.", nil, nil)
	require.NoError(t, err)
	require.Equal(t, DNSSECIndeterminate, status)
}

func TestDNSSECValidatorRRSetWithoutMaterialIsIndeterminate(t *testing.T) {
	validator := NewDNSSECValidator(func() time.Time { return time.Unix(1_700_000_000, 0) })
	rrset := []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}}}
	status, err := validator.ValidateRRSet(rrset, nil, nil)
	require.NoError(t, err)
	require.Equal(t, DNSSECIndeterminate, status)
}

func TestDNSSECValidatorRejectsNonUniformRRSet(t *testing.T) {
	validator := NewDNSSECValidator(nil)
	rrset := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "one.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}},
		&dns.A{Hdr: dns.RR_Header{Name: "two.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}},
	}
	status, err := validator.ValidateRRSet(rrset, nil, nil)
	require.Error(t, err)
	require.Equal(t, DNSSECBogus, status)
}
