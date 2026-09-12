package gcdns

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestProveNSECDSAbsence(t *testing.T) {
	record := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "unsigned.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET},
		NextDomain: "zzz.test.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
	}
	require.NoError(t, proveNSECDSAbsence([]*dns.NSEC{record}, "unsigned.test."))

	withDS := *record
	withDS.TypeBitMap = append([]uint16(nil), record.TypeBitMap...)
	withDS.TypeBitMap = append(withDS.TypeBitMap, dns.TypeDS)
	require.ErrorContains(t, proveNSECDSAbsence([]*dns.NSEC{&withDS}, "unsigned.test."), "advertises DS")

	withoutNS := *record
	withoutNS.TypeBitMap = []uint16{dns.TypeRRSIG, dns.TypeNSEC}
	require.ErrorContains(t, proveNSECDSAbsence([]*dns.NSEC{&withoutNS}, "unsigned.test."), "does not prove a delegation")
}

func TestProveNSEC3DSAbsence(t *testing.T) {
	zone := "unsigned.test."
	hash := dns.HashName(zone, dns.SHA1, 0, "")
	record := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: strings.ToUpper(hash) + ".test.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET},
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations: 0,
		SaltLength: 0,
		HashLength: 20,
		NextDomain: strings.Repeat("V", 32),
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC3},
	}
	require.NoError(t, proveNSEC3DSAbsence([]*dns.NSEC3{record}, zone))

	optOut := *record
	optOut.Flags = 1
	require.ErrorContains(t, proveNSEC3DSAbsence([]*dns.NSEC3{&optOut}, zone), "opt-out")
}

func TestDNSSECIterativeResolverTransitionsToInsecureWithoutDNSKEYFetch(t *testing.T) {
	rootTarget := ResolverTarget{ID: "root", Address: "192.0.2.1:53"}
	childTargetID := "ns.test./192.0.2.53"
	rootDNSKEY := dnssecReply(".", dns.TypeDNSKEY)
	referral := dnssecReply("www.unsigned.test.", dns.TypeA)
	referral.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: "ns.test."}}
	referral.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}, A: net.ParseIP("192.0.2.53").To4()}}
	final := dnssecReply("www.unsigned.test.", dns.TypeA)
	final.Authoritative = true
	final.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "www.unsigned.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 90}, A: net.ParseIP("203.0.113.20").To4()}}

	executor := &dnssecScriptedResolver{responses: map[string]*dns.Msg{
		"root|.|DNSKEY":                           rootDNSKEY,
		"root|www.unsigned.test.|A":              referral,
		childTargetID + "|www.unsigned.test.|A": final,
	}}
	scheduler, err := NewResolverScheduler(ResolverSchedulerConfig{MaxParallel: 1, AttemptTimeout: time.Second}, executor, []ResolverTarget{rootTarget})
	require.NoError(t, err)
	validator := &dnssecValidatorStub{rootKeys: []*dns.DNSKEY{authenticatedTestKey(".")}}
	resolver, err := NewDNSSECIterativeResolver(IterativeResolverConfig{MaxDepth: 6}, scheduler, []ResolverTarget{rootTarget}, validator, DefaultRootTrustAnchors())
	require.NoError(t, err)

	res, err := resolver.Resolve(context.Background(), iterativeQuery("www.unsigned.test.", dns.TypeA))
	require.NoError(t, err)
	require.Equal(t, DNSSECInsecure, res.DNSSECStatus)
	require.Equal(t, 90*time.Second, res.CacheTTL)
	require.Equal(t, 1, validator.insecureCalls)
	require.Zero(t, validator.delegationCalls)
	require.Equal(t, []string{"root|.|DNSKEY", "root|www.unsigned.test.|A", childTargetID + "|www.unsigned.test.|A"}, executor.requests)
}

func TestDNSSECIterativeResolverDoesNotRegainTrustBelowInsecureDelegation(t *testing.T) {
	rootTarget := ResolverTarget{ID: "root", Address: "192.0.2.1:53"}
	unsignedTargetID := "ns.test./192.0.2.53"
	deepTargetID := "ns.deep.test./192.0.2.54"
	rootDNSKEY := dnssecReply(".", dns.TypeDNSKEY)

	firstReferral := dnssecReply("www.deep.test.", dns.TypeA)
	firstReferral.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns.test."}}
	firstReferral.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns.test.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.53").To4()}}

	secondReferral := dnssecReply("www.deep.test.", dns.TypeA)
	secondReferral.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "deep.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns.deep.test."},
		&dns.DS{Hdr: dns.RR_Header{Name: "deep.test.", Rrtype: dns.TypeDS, Class: dns.ClassINET}, KeyTag: 1, Algorithm: dns.RSASHA256, DigestType: dns.SHA256, Digest: "00"},
	}
	secondReferral.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns.deep.test.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.54").To4()}}

	final := dnssecReply("www.deep.test.", dns.TypeA)
	final.Authoritative = true
	final.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "www.deep.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 45}, A: net.ParseIP("203.0.113.45").To4()}}

	executor := &dnssecScriptedResolver{responses: map[string]*dns.Msg{
		"root|.|DNSKEY":                         rootDNSKEY,
		"root|www.deep.test.|A":                firstReferral,
		unsignedTargetID + "|www.deep.test.|A": secondReferral,
		deepTargetID + "|www.deep.test.|A":     final,
	}}
	scheduler, err := NewResolverScheduler(ResolverSchedulerConfig{MaxParallel: 1, AttemptTimeout: time.Second}, executor, []ResolverTarget{rootTarget})
	require.NoError(t, err)
	validator := &dnssecValidatorStub{rootKeys: []*dns.DNSKEY{authenticatedTestKey(".")}}
	resolver, err := NewDNSSECIterativeResolver(IterativeResolverConfig{MaxDepth: 8}, scheduler, []ResolverTarget{rootTarget}, validator, DefaultRootTrustAnchors())
	require.NoError(t, err)

	res, err := resolver.Resolve(context.Background(), iterativeQuery("www.deep.test.", dns.TypeA))
	require.NoError(t, err)
	require.Equal(t, DNSSECInsecure, res.DNSSECStatus)
	require.Equal(t, 1, validator.insecureCalls)
	require.Zero(t, validator.delegationCalls)
	require.Equal(t, "root|.|DNSKEY", executor.requests[0])
	for _, request := range executor.requests[1:] {
		require.NotContains(t, request, "|DNSKEY")
	}
}
