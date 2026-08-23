package gcdns

import (
	"crypto"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func compactNSECTestRecord(t *testing.T, owner, next string, bitmap []uint16, key *dns.DNSKEY, signer crypto.Signer) (*dns.NSEC, *dns.RRSIG) {
	t.Helper()
	record := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: dns.Fqdn(next),
		TypeBitMap: bitmap,
	}
	return record, signNSECTestRecord(t, record, key, signer)
}

func TestAuthenticateNSECNXDOMAINCompactUsesImplicitZoneEncloser(t *testing.T) {
	zone := "example.test."
	qname := "x.c.example.test."
	key, signer := nsec3TestKey(t, zone)
	nameProof, nameSig := compactNSECTestRecord(t, "a.example.test.", "d.example.test.", []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC}, key, signer)
	wildcardProof, wildcardSig := compactNSECTestRecord(t, "!.example.test.", "a.example.test.", []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC}, key, signer)
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = []dns.RR{nameProof, nameSig, wildcardProof, wildcardSig}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	legacyStatus, legacyErr := validator.AuthenticateNSECNXDOMAIN(msg, qname, []*dns.DNSKEY{key})
	require.NoError(t, legacyErr)
	require.Equal(t, DNSSECIndeterminate, legacyStatus)

	status, err := validator.AuthenticateNSECNXDOMAINCompact(msg, qname, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)
}

func TestAuthenticateTerminalAnswerUsesCompactNSECNXDOMAIN(t *testing.T) {
	zone := "example.test."
	qname := "x.c.example.test."
	key, signer := nsec3TestKey(t, zone)
	nameProof, nameSig := compactNSECTestRecord(t, "a.example.test.", "d.example.test.", []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC}, key, signer)
	wildcardProof, wildcardSig := compactNSECTestRecord(t, "!.example.test.", "a.example.test.", []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC}, key, signer)
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = []dns.RR{nameProof, nameSig, wildcardProof, wildcardSig}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)
}

func TestAuthenticateNSECNXDOMAINCompactRequiresAncestorProof(t *testing.T) {
	zone := "example.test."
	qname := "x.c.example.test."
	key, signer := nsec3TestKey(t, zone)
	nameProof, nameSig := compactNSECTestRecord(t, "b.c.example.test.", "z.c.example.test.", []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC}, key, signer)
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = []dns.RR{nameProof, nameSig}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateNSECNXDOMAINCompact(msg, qname, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECIndeterminate, status)
}

func TestAuthenticateNSECNXDOMAINCompactRejectsExistingWildcard(t *testing.T) {
	zone := "example.test."
	qname := "x.c.example.test."
	key, signer := nsec3TestKey(t, zone)
	nameProof, nameSig := compactNSECTestRecord(t, "a.example.test.", "d.example.test.", []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC}, key, signer)
	wildcard, wildcardSig := compactNSECTestRecord(t, "*.example.test.", "a.example.test.", []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC}, key, signer)
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = []dns.RR{nameProof, nameSig, wildcard, wildcardSig}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateNSECNXDOMAINCompact(msg, qname, []*dns.DNSKEY{key})
	require.ErrorContains(t, err, "wildcard owner")
	require.Equal(t, DNSSECBogus, status)
}

func TestAuthenticateNSECNXDOMAINCompactRejectsDNAMEEncloser(t *testing.T) {
	zone := "example.test."
	qname := "x.child.example.test."
	key, signer := nsec3TestKey(t, zone)
	proof, sig := compactNSECTestRecord(t, "child.example.test.", "z.example.test.", []uint16{dns.TypeDNAME, dns.TypeRRSIG, dns.TypeNSEC}, key, signer)
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = []dns.RR{proof, sig}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateNSECNXDOMAINCompact(msg, qname, []*dns.DNSKEY{key})
	require.ErrorContains(t, err, "DNAME")
	require.Equal(t, DNSSECBogus, status)
}

func TestAuthenticateNSECNXDOMAINCompactRejectsAncestorDelegation(t *testing.T) {
	zone := "example.test."
	qname := "x.child.example.test."
	key, signer := nsec3TestKey(t, zone)
	proof, sig := compactNSECTestRecord(t, "child.example.test.", "z.example.test.", []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC}, key, signer)
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = []dns.RR{proof, sig}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateNSECNXDOMAINCompact(msg, qname, []*dns.DNSKEY{key})
	require.ErrorContains(t, err, "ancestor delegation")
	require.Equal(t, DNSSECBogus, status)
}
