package gcdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestNSECHasType(t *testing.T) {
	nsec := &dns.NSEC{TypeBitMap: []uint16{dns.TypeA, dns.TypeNS, dns.TypeRRSIG}}
	require.True(t, nsecHasType(nsec, dns.TypeNS))
	require.False(t, nsecHasType(nsec, dns.TypeDS))
}

func TestAuthenticateInsecureDelegationNSECMissingProofIsIndeterminate(t *testing.T) {
	v := NewDNSSECValidator(time.Now)
	status, err := v.AuthenticateInsecureDelegationNSEC("unsigned.test.", new(dns.Msg), []*dns.DNSKEY{rootKSK2017()})
	require.NoError(t, err)
	require.Equal(t, DNSSECIndeterminate, status)
}

func TestAuthenticateInsecureDelegationNSECRejectsUnsignedProof(t *testing.T) {
	v := NewDNSSECValidator(time.Now)
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{&dns.NSEC{
		Hdr: dns.RR_Header{Name: "unsigned.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 60},
		NextDomain: "zzz.unsigned.test.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
	}}
	status, err := v.AuthenticateInsecureDelegationNSEC("unsigned.test.", msg, []*dns.DNSKEY{rootKSK2017()})
	require.Error(t, err)
	require.Equal(t, DNSSECBogus, status)
}

func TestAuthenticateInsecureDelegationNSECRejectsDSBitmap(t *testing.T) {
	v := NewDNSSECValidator(time.Now)
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{&dns.NSEC{
		Hdr: dns.RR_Header{Name: "signed.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 60},
		NextDomain: "zzz.signed.test.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeDS, dns.TypeRRSIG, dns.TypeNSEC},
	}}
	status, err := v.AuthenticateInsecureDelegationNSEC("signed.test.", msg, []*dns.DNSKEY{rootKSK2017()})
	require.NoError(t, err)
	require.Equal(t, DNSSECIndeterminate, status)
}

func TestAuthenticateNSECNODATARequiresExactSignedProof(t *testing.T) {
	v := NewDNSSECValidator(time.Now)
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeSuccess
	msg.Ns = []dns.RR{&dns.NSEC{
		Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 60},
		NextDomain: "zzz.example.test.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
	}}
	status, err := v.AuthenticateNSECNODATA(msg, "example.test.", dns.TypeAAAA, []*dns.DNSKEY{rootKSK2017()})
	require.Error(t, err)
	require.Equal(t, DNSSECBogus, status)
}
