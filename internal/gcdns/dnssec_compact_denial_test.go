package gcdns

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func compactDenialTestNSEC(t *testing.T, qname string, bitmap []uint16) (*dns.NSEC, *dns.RRSIG, *dns.DNSKEY) {
	t.Helper()
	zone := "example.test."
	key, signer := nsec3TestKey(t, zone)
	record := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "z.example.test.",
		TypeBitMap: bitmap,
	}
	return record, signNSECTestRecord(t, record, key, signer), key
}

func TestAuthenticateCompactDenialNSEC(t *testing.T) {
	qname := "missing.example.test."
	record, sig, key := compactDenialTestNSEC(t, qname, []uint16{dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNXNAME})
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeAAAA)
	msg.Rcode = dns.RcodeSuccess
	msg.Ns = []dns.RR{record, sig}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, handled, err := validator.AuthenticateCompactDenial(msg, qname, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.True(t, handled)
	require.Equal(t, DNSSECSecure, status)
}

func TestAuthenticateCompactDenialNSECRejectsExtraType(t *testing.T) {
	qname := "missing.example.test."
	record, sig, key := compactDenialTestNSEC(t, qname, []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNXNAME})
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeAAAA)
	msg.Rcode = dns.RcodeSuccess
	msg.Ns = []dns.RR{record, sig}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, handled, err := validator.AuthenticateCompactDenial(msg, qname, []*dns.DNSKEY{key})
	require.ErrorContains(t, err, "not exactly")
	require.True(t, handled)
	require.Equal(t, DNSSECBogus, status)
}

func TestAuthenticateCompactDenialOrdinaryNODATANotHandled(t *testing.T) {
	qname := "existing.example.test."
	record, sig, key := compactDenialTestNSEC(t, qname, []uint16{dns.TypeRRSIG, dns.TypeNSEC})
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeAAAA)
	msg.Rcode = dns.RcodeSuccess
	msg.Ns = []dns.RR{record, sig}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, handled, err := validator.AuthenticateCompactDenial(msg, qname, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.False(t, handled)
	require.Equal(t, DNSSECIndeterminate, status)
}

func TestAuthenticateCompactDenialNSEC3(t *testing.T) {
	zone := "example.test."
	qname := "missing.example.test."
	key, signer := nsec3TestKey(t, zone)
	record := nsec3TestRecord(qname, zone, []uint16{dns.TypeNXNAME})
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeAAAA)
	msg.Rcode = dns.RcodeSuccess
	msg.Ns = []dns.RR{record, signNSEC3TestRecord(t, record, key, signer)}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, handled, err := validator.AuthenticateCompactDenial(msg, qname, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.True(t, handled)
	require.Equal(t, DNSSECSecure, status)
}

func TestAuthenticateCompactDenialNSEC3RejectsExtraType(t *testing.T) {
	zone := "example.test."
	qname := "missing.example.test."
	key, signer := nsec3TestKey(t, zone)
	record := nsec3TestRecord(qname, zone, []uint16{dns.TypeA, dns.TypeNXNAME})
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeAAAA)
	msg.Rcode = dns.RcodeSuccess
	msg.Ns = []dns.RR{record, signNSEC3TestRecord(t, record, key, signer)}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, handled, err := validator.AuthenticateCompactDenial(msg, qname, []*dns.DNSKEY{key})
	require.ErrorContains(t, err, "not exactly NXNAME")
	require.True(t, handled)
	require.Equal(t, DNSSECBogus, status)
}

func TestAuthenticateTerminalAnswerUsesCompactDenial(t *testing.T) {
	qname := "missing.example.test."
	record, sig, key := compactDenialTestNSEC(t, qname, []uint16{dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNXNAME})
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeAAAA)
	msg.Rcode = dns.RcodeSuccess
	msg.Ns = []dns.RR{record, sig}

	validator := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := validator.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)
}

func TestCompactDenialNXNAMEQueryReturnsFORMERR(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.test.", dns.TypeNXNAME)
	result, handled := compactDenialQueryResponse(&Request{Message: query})
	require.True(t, handled)
	require.NotNil(t, result)
	require.Equal(t, dns.RcodeFormatError, result.Message.Rcode)
	require.Equal(t, query.Id, result.Message.Id)
}

func TestIterativeResolverRejectsNXNAMEWithoutExchange(t *testing.T) {
	calls := 0
	exchanger := exchangeFunc(func(_ context.Context, _ string, _ *dns.Msg) (*dns.Msg, error) {
		calls++
		return nil, nil
	})
	resolver, err := NewIterativeResolver(exchanger, IterativeResolverConfig{
		RootServers:    []string{"192.0.2.53:53"},
		MaxDepth:       4,
		AttemptTimeout: time.Second,
		MaxConcurrent:  1,
	})
	require.NoError(t, err)
	query := new(dns.Msg)
	query.SetQuestion("example.test.", dns.TypeNXNAME)
	result, err := resolver.Resolve(context.Background(), &Request{Message: query, Transport: TransportDNS})
	require.NoError(t, err)
	require.Zero(t, calls)
	require.NotNil(t, result)
	require.Equal(t, dns.RcodeFormatError, result.Message.Rcode)
}
