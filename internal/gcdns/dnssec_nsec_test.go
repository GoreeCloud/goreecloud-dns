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
		Hdr:        dns.RR_Header{Name: "unsigned.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 60},
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
		Hdr:        dns.RR_Header{Name: "signed.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 60},
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
		Hdr:        dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 60},
		NextDomain: "zzz.example.test.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
	}}
	status, err := v.AuthenticateNSECNODATA(msg, "example.test.", dns.TypeAAAA, []*dns.DNSKEY{rootKSK2017()})
	require.Error(t, err)
	require.Equal(t, DNSSECBogus, status)
}

func TestCanonicalDNSNameCompareUsesRightmostLabelsFirst(t *testing.T) {
	require.Less(t, canonicalDNSNameCompare("example.test.", "a.example.test."), 0)
	require.Less(t, canonicalDNSNameCompare("a.example.test.", "b.example.test."), 0)
	require.Equal(t, 0, canonicalDNSNameCompare("WWW.Example.Test.", "www.example.test."))
}

func TestNSECCoversOrdinaryInterval(t *testing.T) {
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "alpha.example.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET},
		NextDomain: "omega.example.test.",
	}
	require.True(t, nsecCoversName(nsec, "mid.example.test."))
	require.False(t, nsecCoversName(nsec, "alpha.example.test."))
	require.False(t, nsecCoversName(nsec, "omega.example.test."))
	require.False(t, nsecCoversName(nsec, "zulu.example.test."))
}

func TestNSECCoversWrapAroundInterval(t *testing.T) {
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "zulu.example.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET},
		NextDomain: "alpha.example.test.",
	}
	require.True(t, nsecCoversName(nsec, "zzzz.example.test."))
	require.True(t, nsecCoversName(nsec, "aardvark.example.test."))
	require.False(t, nsecCoversName(nsec, "mid.example.test."))
}

func TestClosestEncloserAndNextCloserSelection(t *testing.T) {
	records := []*dns.NSEC{
		{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET}, NextDomain: "z.example.test."},
		{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET}, NextDomain: "z.test."},
	}
	closest := closestEncloserNSEC("www.deep.example.test.", "example.test.", records)
	require.NotNil(t, closest)
	require.Equal(t, "example.test.", dns.Fqdn(closest.Hdr.Name))
	next, ok := nextCloserName("www.deep.example.test.", "example.test.")
	require.True(t, ok)
	require.Equal(t, "deep.example.test.", next)
}

func TestAuthenticateNSECNXDOMAINMissingProofIsIndeterminate(t *testing.T) {
	v := NewDNSSECValidator(time.Now)
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeNameError
	status, err := v.AuthenticateNSECNXDOMAIN(msg, "missing.example.test.", []*dns.DNSKEY{testDNSKEY("example.test.", 1)})
	require.NoError(t, err)
	require.Equal(t, DNSSECIndeterminate, status)
}

func TestAuthenticateNSECNXDOMAINRejectsQuestionOutsideAuthenticatedZone(t *testing.T) {
	v := NewDNSSECValidator(time.Now)
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeNameError
	status, err := v.AuthenticateNSECNXDOMAIN(msg, "missing.other.test.", []*dns.DNSKEY{testDNSKEY("example.test.", 1)})
	require.Error(t, err)
	require.Equal(t, DNSSECBogus, status)
}
