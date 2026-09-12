package gcdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestAuthenticateTerminalAnswerNegativeRemainsIndeterminate(t *testing.T) {
	v := NewDNSSECValidator(time.Now)
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeNameError
	status, err := v.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{{}})
	require.NoError(t, err)
	require.Equal(t, DNSSECIndeterminate, status)
}

func TestAuthenticateTerminalAnswerEmptyNoErrorWithoutProofIsIndeterminate(t *testing.T) {
	v := NewDNSSECValidator(time.Now)
	msg := new(dns.Msg)
	msg.SetQuestion("example.test.", dns.TypeAAAA)
	msg.Rcode = dns.RcodeSuccess
	status, err := v.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{rootKSK2017()})
	require.NoError(t, err)
	require.Equal(t, DNSSECIndeterminate, status)
}

func TestAuthenticateTerminalAnswerNSEC3NODATA(t *testing.T) {
	zone := "example.test."
	qname := "host.example.test."
	key, signer := nsec3TestKey(t, zone)
	record := nsec3TestRecord(qname, zone, []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC3})
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeAAAA)
	msg.Rcode = dns.RcodeSuccess
	msg.Ns = []dns.RR{record, signNSEC3TestRecord(t, record, key, signer)}

	v := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := v.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)
}

func TestAuthenticateTerminalAnswerNSEC3NXDOMAIN(t *testing.T) {
	zone := "example.test."
	qname := "missing.example.test."
	key, signer := nsec3TestKey(t, zone)
	record := nsec3TestRecord(zone, zone, []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC3})
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = []dns.RR{record, signNSEC3TestRecord(t, record, key, signer)}

	v := NewDNSSECValidator(func() time.Time { return nsec3TestNow })
	status, err := v.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{key})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)
}

func TestAuthenticateTerminalAnswerRequiresKeys(t *testing.T) {
	v := NewDNSSECValidator(time.Now)
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}}}
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET}, Flags: 257, Protocol: 3, Algorithm: dns.RSASHA256}
	status, err := v.AuthenticateTerminalAnswer(msg, nil)
	require.Error(t, err)
	require.Equal(t, DNSSECBogus, status)
	_ = key
}

func TestAuthenticateTerminalAnswerUnsignedPositiveIsBogus(t *testing.T) {
	v := NewDNSSECValidator(time.Now)
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}}}
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET}, Flags: 257, Protocol: 3, Algorithm: dns.RSASHA256}
	status, err := v.AuthenticateTerminalAnswer(msg, []*dns.DNSKEY{key})
	require.Error(t, err)
	require.Equal(t, DNSSECBogus, status)
}

func TestAuthenticateTerminalAnswerNilResponseIsBogus(t *testing.T) {
	v := NewDNSSECValidator(time.Now)
	status, err := v.AuthenticateTerminalAnswer(nil, nil)
	require.Error(t, err)
	require.Equal(t, DNSSECBogus, status)
}
