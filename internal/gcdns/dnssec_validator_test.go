package gcdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDNSSECValidatorMatchDS(t *testing.T) {
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: "AwEAAc4M9j7xQ8v7Xqg0uO2lXxYgG6hBzq9P0y0kYQ==",
	}
	ds := key.ToDS(dns.SHA256)
	require.NotNil(t, ds)

	validator := NewDNSSECValidator(nil)
	status, err := validator.MatchDS("example.test.", []*dns.DS{ds}, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)

	bad := *ds
	bad.Digest = "00" + bad.Digest[2:]
	status, err = validator.MatchDS("example.test.", []*dns.DS{&bad}, []*dns.DNSKEY{key})
	require.Error(t, err)
	require.Equal(t, DNSSECBogus, status)
}

func TestDNSSECValidatorUnsignedDelegationIsInsecure(t *testing.T) {
	validator := NewDNSSECValidator(nil)
	status, err := validator.MatchDS("unsigned.test.", nil, nil)
	require.NoError(t, err)
	require.Equal(t, DNSSECInsecure, status)
}

func TestDNSSECValidatorRRSetWithoutMaterialIsIndeterminate(t *testing.T) {
	validator := NewDNSSECValidator(func() time.Time { return time.Unix(1_700_000_000, 0) })
	rrset := []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
	}}
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
