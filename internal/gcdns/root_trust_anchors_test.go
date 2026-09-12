package gcdns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDefaultRootTrustAnchorsIncludesCurrentRolloverKeys(t *testing.T) {
	anchors := DefaultRootTrustAnchors()
	require.Len(t, anchors, 2)

	byTag := make(map[uint16]*dns.DS, len(anchors))
	for _, anchor := range anchors {
		byTag[anchor.KeyTag] = anchor
		require.Equal(t, ".", anchor.Hdr.Name)
		require.Equal(t, uint8(dns.RSASHA256), anchor.Algorithm)
		require.Equal(t, uint8(dns.SHA256), anchor.DigestType)
	}

	require.Equal(t, rootKSK2017Digest, byTag[20326].Digest)
	require.Equal(t, rootKSK2024Digest, byTag[38696].Digest)
}

func TestMatchingTrustAnchorKeysAcceptsIANA2017KSK(t *testing.T) {
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 172800},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
	}

	matched := matchingTrustAnchorKeys(DefaultRootTrustAnchors(), []*dns.DNSKEY{key})
	require.Len(t, matched, 1)
	require.Equal(t, uint16(20326), matched[0].KeyTag())
}

func TestMatchingTrustAnchorKeysRejectsUntrustedKey(t *testing.T) {
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: "AwEAAQ==",
	}
	require.Empty(t, matchingTrustAnchorKeys(DefaultRootTrustAnchors(), []*dns.DNSKEY{key}))
}

func TestValidateRootDNSKEYRejectsMissingMaterial(t *testing.T) {
	validator := NewDNSSECValidator(nil)
	status, keys, err := validator.ValidateRootDNSKEY(new(dns.Msg), DefaultRootTrustAnchors())
	require.Error(t, err)
	require.Equal(t, DNSSECBogus, status)
	require.Nil(t, keys)
}
