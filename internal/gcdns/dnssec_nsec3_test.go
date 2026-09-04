package gcdns

import (
	"crypto"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

var nsec3TestNow = time.Unix(1_800_000_000, 0)

func nsec3TestKey(t *testing.T, zone string) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     dns.ZONE | dns.SEP,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	privateKey, err := key.Generate(256)
	require.NoError(t, err)
	signer, ok := privateKey.(crypto.Signer)
	require.True(t, ok)
	return key, signer
}

func nsec3TestRecord(name, zone string, bitmap []uint16) *dns.NSEC3 {
	hash := dns.HashName(dns.Fqdn(name), dns.SHA1, 0, "")
	return &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: hash + "." + dns.Fqdn(zone), Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations: 0,
		SaltLength: 0,
		Salt:       "",
		HashLength: 20,
		NextDomain: hash,
		TypeBitMap: bitmap,
	}
}

func signNSEC3TestRecord(t *testing.T, record *dns.NSEC3, key *dns.DNSKEY, signer crypto.Signer) *dns.RRSIG {
	t.Helper()
	sig := &dns.RRSIG{
		Algorithm:  key.Algorithm,
		Inception:  uint32(nsec3TestNow.Add(-time.Hour).Unix()),
		Expiration: uint32(nsec3TestNow.Add(time.Hour).Unix()),
		KeyTag:     key.KeyTag(),
		SignerName: key.Hdr.Name,
	}
	require.NoError(t, sig.Sign(signer, []dns.RR{record}))
	return sig
}

func nsec3TestDelegationNS(child string) *dns.NS {
	child = dns.Fqdn(child)
	return &dns.NS{
		Hdr: dns.RR_Header{Name: child, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
		Ns:  "ns1." + child,
	}
}

func TestAuthenticateNSEC3NODATA(t *testing.T) {
	zone := "example.test."
	qname := "host.example.test."
	key, signer := nsec3TestKey(t, zone)
	record := nsec3TestRecord(qname, zone, []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC3})
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeSuccess
	msg.Ns = []dns.RR{record, signNSEC3TestRecord(t, record, key, signer)}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateNSEC3NODATA(msg, qname, dns.TypeAAAA, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)
}

func TestAuthenticateNSEC3NODATARejectsExistingType(t *testing.T) {
	zone := "example.test."
	qname := "host.example.test."
	key, signer := nsec3TestKey(t, zone)
	record := nsec3TestRecord(qname, zone, []uint16{dns.TypeAAAA, dns.TypeRRSIG, dns.TypeNSEC3})
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeSuccess
	msg.Ns = []dns.RR{record, signNSEC3TestRecord(t, record, key, signer)}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateNSEC3NODATA(msg, qname, dns.TypeAAAA, []*dns.DNSKEY{key})
	require.Error(t, err)
	require.Equal(t, DNSSECBogus, status)
}

func TestAuthenticateNSEC3NXDOMAIN(t *testing.T) {
	zone := "example.test."
	qname := "missing.example.test."
	key, signer := nsec3TestKey(t, zone)
	// A one-record NSEC3 ring establishes the zone apex as closest encloser and
	// covers every other hash in the ring, including next-closer and wildcard.
	record := nsec3TestRecord(zone, zone, []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC3})
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = []dns.RR{record, signNSEC3TestRecord(t, record, key, signer)}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateNSEC3NXDOMAIN(msg, qname, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)
}

func TestAuthenticateNSEC3NXDOMAINRejectsExistingOwnerHash(t *testing.T) {
	zone := "example.test."
	qname := "missing.example.test."
	key, signer := nsec3TestKey(t, zone)
	record := nsec3TestRecord(qname, zone, []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC3})
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = []dns.RR{record, signNSEC3TestRecord(t, record, key, signer)}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateNSEC3NXDOMAIN(msg, qname, []*dns.DNSKEY{key})
	require.Error(t, err)
	require.Equal(t, DNSSECBogus, status)
}

func TestAuthenticateInsecureDelegationNSEC3(t *testing.T) {
	zone := "example.test."
	child := "unsigned.example.test."
	key, signer := nsec3TestKey(t, zone)
	record := nsec3TestRecord(child, zone, []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC3})
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{record, signNSEC3TestRecord(t, record, key, signer)}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateInsecureDelegationNSEC3(child, msg, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECInsecure, status)
}

func TestAuthenticateInsecureDelegationNSEC3ExactOptOut(t *testing.T) {
	zone := "example.test."
	child := "unsigned.example.test."
	key, signer := nsec3TestKey(t, zone)
	record := nsec3TestRecord(child, zone, []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC3})
	record.Flags = nsec3OptOutFlag
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{record, signNSEC3TestRecord(t, record, key, signer)}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateInsecureDelegationNSEC3(child, msg, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECInsecure, status)
}

func TestAuthenticateInsecureDelegationNSEC3OptOutCoverage(t *testing.T) {
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
	status, err := validator.AuthenticateInsecureDelegationNSEC3(child, msg, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECInsecure, status)
}

func TestAuthenticateInsecureDelegationNSEC3OptOutRequiresReferralNS(t *testing.T) {
	zone := "example.test."
	child := "unsigned.example.test."
	key, signer := nsec3TestKey(t, zone)
	proof := nsec3TestRecord(zone, zone, []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC3})
	proof.Flags = nsec3OptOutFlag
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{proof, signNSEC3TestRecord(t, proof, key, signer)}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateInsecureDelegationNSEC3(child, msg, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECIndeterminate, status)
}

func TestAuthenticateInsecureDelegationNSEC3OptOutRequiresFlag(t *testing.T) {
	zone := "example.test."
	child := "unsigned.example.test."
	key, signer := nsec3TestKey(t, zone)
	proof := nsec3TestRecord(zone, zone, []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC3})
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{
		nsec3TestDelegationNS(child),
		proof,
		signNSEC3TestRecord(t, proof, key, signer),
	}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateInsecureDelegationNSEC3(child, msg, []*dns.DNSKEY{key})
	require.ErrorContains(t, err, "opt-out flag")
	require.Equal(t, DNSSECBogus, status)
}

func TestAuthenticateInsecureDelegationNSEC3RejectsDSBitmap(t *testing.T) {
	zone := "example.test."
	child := "signed.example.test."
	key, signer := nsec3TestKey(t, zone)
	record := nsec3TestRecord(child, zone, []uint16{dns.TypeNS, dns.TypeDS, dns.TypeRRSIG, dns.TypeNSEC3})
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{record, signNSEC3TestRecord(t, record, key, signer)}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateInsecureDelegationNSEC3(child, msg, []*dns.DNSKEY{key})
	require.Error(t, err)
	require.Equal(t, DNSSECBogus, status)
}

func TestAuthenticateNSEC3OptOutFailsClosed(t *testing.T) {
	zone := "example.test."
	qname := "host.example.test."
	key, _ := nsec3TestKey(t, zone)
	record := nsec3TestRecord(qname, zone, nil)
	record.Flags = nsec3OptOutFlag
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeSuccess
	msg.Ns = []dns.RR{record}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateNSEC3NODATA(msg, qname, dns.TypeAAAA, []*dns.DNSKEY{key})
	require.ErrorContains(t, err, "opt-out")
	require.Equal(t, DNSSECBogus, status)
}

func TestValidateNSEC3SetRejectsUnknownFlags(t *testing.T) {
	zone := "example.test."
	record := nsec3TestRecord("host.example.test.", zone, nil)
	record.Flags = 2
	require.ErrorContains(t, validateNSEC3DelegationSet([]*dns.NSEC3{record}, zone), "unsupported NSEC3 flags")
}

func TestValidateNSEC3SetRejectsInconsistentParameters(t *testing.T) {
	zone := "example.test."
	first := nsec3TestRecord("one.example.test.", zone, nil)
	second := nsec3TestRecord("two.example.test.", zone, nil)
	second.Iterations = 1
	require.ErrorContains(t, validateNSEC3Set([]*dns.NSEC3{first, second}, zone), "inconsistent")
}

func TestNSEC3OwnerZone(t *testing.T) {
	record := nsec3TestRecord("host.example.test.", "example.test.", nil)
	require.Equal(t, "example.test.", nsec3OwnerZone(record))
	require.True(t, strings.HasSuffix(dns.CanonicalName(record.Hdr.Name), "example.test."))
}
