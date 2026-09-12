package gcdns

import (
	"crypto"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func wildcardTestAnswer(t *testing.T, qname, wildcard string, key *dns.DNSKEY, signer crypto.Signer) (*dns.A, *dns.RRSIG) {
	t.Helper()
	original := &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(wildcard), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{192, 0, 2, 10},
	}
	sig := &dns.RRSIG{
		Algorithm:  key.Algorithm,
		Inception:  uint32(nsec3TestNow.Add(-time.Hour).Unix()),
		Expiration: uint32(nsec3TestNow.Add(time.Hour).Unix()),
		KeyTag:     key.KeyTag(),
		SignerName: key.Hdr.Name,
	}
	require.NoError(t, sig.Sign(signer, []dns.RR{original}))

	expanded := dns.Copy(original).(*dns.A)
	expanded.Hdr.Name = dns.Fqdn(qname)
	sig.Hdr.Name = dns.Fqdn(qname)
	return expanded, sig
}

func signNSECTestRecord(t *testing.T, record *dns.NSEC, key *dns.DNSKEY, signer crypto.Signer) *dns.RRSIG {
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

func wildcardTestNSEC(t *testing.T, owner, next string, key *dns.DNSKEY, signer crypto.Signer) (*dns.NSEC, *dns.RRSIG) {
	t.Helper()
	record := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: dns.Fqdn(next),
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
	}
	return record, signNSECTestRecord(t, record, key, signer)
}

func directTestAnswer(t *testing.T, qname string, key *dns.DNSKEY, signer crypto.Signer) (*dns.A, *dns.RRSIG) {
	t.Helper()
	record := &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{192, 0, 2, 20},
	}
	sig := &dns.RRSIG{
		Algorithm:  key.Algorithm,
		Inception:  uint32(nsec3TestNow.Add(-time.Hour).Unix()),
		Expiration: uint32(nsec3TestNow.Add(time.Hour).Unix()),
		KeyTag:     key.KeyTag(),
		SignerName: key.Hdr.Name,
	}
	require.NoError(t, sig.Sign(signer, []dns.RR{record}))
	return record, sig
}

func TestWildcardClosestEncloser(t *testing.T) {
	closest, ok := wildcardClosestEncloser("a.z.w.example.test.", 3)
	require.True(t, ok)
	require.Equal(t, "w.example.test.", closest)

	_, ok = wildcardClosestEncloser("example.test.", 2)
	require.False(t, ok)
}

func TestAuthenticateTerminalAnswerSignedDirectPositive(t *testing.T) {
	zone := "example.test."
	qname := "host.example.test."
	key, signer := nsec3TestKey(t, zone)
	answer, sig := directTestAnswer(t, qname, key, signer)
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = []dns.RR{answer, sig}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)
}

func TestAuthenticateTerminalAnswerLiteralWildcardOwner(t *testing.T) {
	zone := "example.test."
	qname := "*.example.test."
	key, signer := nsec3TestKey(t, zone)
	answer, sig := directTestAnswer(t, qname, key, signer)
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = []dns.RR{answer, sig}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)
}

func TestAuthenticateTerminalAnswerWildcardNSEC(t *testing.T) {
	zone := "example.test."
	qname := "host.example.test."
	key, signer := nsec3TestKey(t, zone)
	answer, answerSig := wildcardTestAnswer(t, qname, "*.example.test.", key, signer)
	proof, proofSig := wildcardTestNSEC(t, "aaa.example.test.", "zzz.example.test.", key, signer)
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = []dns.RR{answer, answerSig}
	msg.Ns = []dns.RR{proof, proofSig}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)
}

func TestAuthenticateTerminalAnswerWildcardNSEC3(t *testing.T) {
	zone := "example.test."
	qname := "host.example.test."
	key, signer := nsec3TestKey(t, zone)
	answer, answerSig := wildcardTestAnswer(t, qname, "*.example.test.", key, signer)
	proof := nsec3TestRecord(zone, zone, []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC3})
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = []dns.RR{answer, answerSig}
	msg.Ns = []dns.RR{proof, signNSEC3TestRecord(t, proof, key, signer)}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)
}

func TestAuthenticateTerminalAnswerWildcardMissingProofFailsClosed(t *testing.T) {
	zone := "example.test."
	qname := "host.example.test."
	key, signer := nsec3TestKey(t, zone)
	answer, answerSig := wildcardTestAnswer(t, qname, "*.example.test.", key, signer)
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = []dns.RR{answer, answerSig}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{key})
	require.ErrorContains(t, err, "wildcard")
	require.Equal(t, DNSSECBogus, status)
}

func TestAuthenticateTerminalAnswerWildcardRejectsExistingCloserName(t *testing.T) {
	zone := "example.test."
	qname := "host.example.test."
	key, signer := nsec3TestKey(t, zone)
	answer, answerSig := wildcardTestAnswer(t, qname, "*.example.test.", key, signer)
	proof, proofSig := wildcardTestNSEC(t, qname, "zzz.example.test.", key, signer)
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = []dns.RR{answer, answerSig}
	msg.Ns = []dns.RR{proof, proofSig}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{key})
	require.ErrorContains(t, err, "closer name")
	require.Equal(t, DNSSECBogus, status)
}

func TestAuthenticateTerminalAnswerWildcardNODATANSEC(t *testing.T) {
	zone := "example.test."
	qname := "host.example.test."
	key, signer := nsec3TestKey(t, zone)
	proof, proofSig := wildcardTestNSEC(t, "*.example.test.", "zzz.example.test.", key, signer)
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeAAAA)
	msg.Rcode = dns.RcodeSuccess
	msg.Ns = []dns.RR{proof, proofSig}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)
}

func TestAuthenticateTerminalAnswerWildcardNODATANSECRejectsExistingType(t *testing.T) {
	zone := "example.test."
	qname := "host.example.test."
	key, signer := nsec3TestKey(t, zone)
	proof := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "*.example.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "zzz.example.test.",
		TypeBitMap: []uint16{dns.TypeAAAA, dns.TypeRRSIG, dns.TypeNSEC},
	}
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeAAAA)
	msg.Rcode = dns.RcodeSuccess
	msg.Ns = []dns.RR{proof, signNSECTestRecord(t, proof, key, signer)}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{key})
	require.ErrorContains(t, err, "bitmap")
	require.Equal(t, DNSSECBogus, status)
}

func TestAuthenticateTerminalAnswerWildcardNODATANSEC3(t *testing.T) {
	zone := "example.test."
	qname := "host.example.test."
	key, signer := nsec3TestKey(t, zone)
	closest := nsec3TestRecord(zone, zone, []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC3})
	wildcard := nsec3TestRecord("*.example.test.", zone, []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC3})
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeAAAA)
	msg.Rcode = dns.RcodeSuccess
	msg.Ns = []dns.RR{
		closest, signNSEC3TestRecord(t, closest, key, signer),
		wildcard, signNSEC3TestRecord(t, wildcard, key, signer),
	}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)
}

func TestAuthenticateTerminalAnswerWildcardNODATANSEC3RejectsExistingType(t *testing.T) {
	zone := "example.test."
	qname := "host.example.test."
	key, signer := nsec3TestKey(t, zone)
	closest := nsec3TestRecord(zone, zone, []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC3})
	wildcard := nsec3TestRecord("*.example.test.", zone, []uint16{dns.TypeAAAA, dns.TypeRRSIG, dns.TypeNSEC3})
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeAAAA)
	msg.Rcode = dns.RcodeSuccess
	msg.Ns = []dns.RR{
		closest, signNSEC3TestRecord(t, closest, key, signer),
		wildcard, signNSEC3TestRecord(t, wildcard, key, signer),
	}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{key})
	require.ErrorContains(t, err, "bitmap")
	require.Equal(t, DNSSECBogus, status)
}
