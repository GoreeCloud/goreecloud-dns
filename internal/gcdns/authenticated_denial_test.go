package gcdns

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func denialSignature(name string, covered uint16, signer string) *dns.RRSIG {
	return &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: covered,
		Algorithm:   dns.RSASHA256,
		SignerName:  dns.Fqdn(signer),
	}
}

func authenticatedTestKey(zone string) *dns.DNSKEY {
	return &dns.DNSKEY{Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET}, Protocol: 3}
}

func TestAuthenticatedDenialNSECNODATA(t *testing.T) {
	validator := &dnssecValidatorStub{}
	resolver := &DNSSECIterativeResolver{validator: validator}
	msg := dnssecReply("host.example.test.", dns.TypeAAAA)
	msg.Authoritative = true
	msg.Ns = []dns.RR{
		&dns.NSEC{
			Hdr:        dns.RR_Header{Name: "host.example.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
			NextDomain: "next.example.test.",
			TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
		},
		denialSignature("host.example.test.", dns.TypeNSEC, "example.test."),
	}

	status, err := resolver.validateAuthenticatedDenial(msg, msg.Question[0], []*dns.DNSKEY{authenticatedTestKey("example.test.")})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)
	require.Equal(t, 1, validator.rrsetCalls)
}

func TestAuthenticatedDenialNSECNODATARejectsExistingType(t *testing.T) {
	resolver := &DNSSECIterativeResolver{validator: &dnssecValidatorStub{}}
	msg := dnssecReply("host.example.test.", dns.TypeA)
	msg.Authoritative = true
	msg.Ns = []dns.RR{
		&dns.NSEC{
			Hdr:        dns.RR_Header{Name: "host.example.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
			NextDomain: "next.example.test.",
			TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
		},
		denialSignature("host.example.test.", dns.TypeNSEC, "example.test."),
	}

	_, err := resolver.validateAuthenticatedDenial(msg, msg.Question[0], []*dns.DNSKEY{authenticatedTestKey("example.test.")})
	require.ErrorContains(t, err, "does not prove NODATA")
}

func TestAuthenticatedDenialNSECNXDOMAIN(t *testing.T) {
	resolver := &DNSSECIterativeResolver{validator: &dnssecValidatorStub{}}
	msg := dnssecReply("missing.example.test.", dns.TypeA)
	msg.Rcode = dns.RcodeNameError
	msg.Authoritative = true
	msg.Ns = []dns.RR{
		&dns.NSEC{
			Hdr:        dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
			NextDomain: "zzz.example.test.",
			TypeBitMap: []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
		},
		denialSignature("example.test.", dns.TypeNSEC, "example.test."),
	}

	status, err := resolver.validateAuthenticatedDenial(msg, msg.Question[0], []*dns.DNSKEY{authenticatedTestKey("example.test.")})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)
}

func TestAuthenticatedDenialRejectsUnsignedNSEC(t *testing.T) {
	resolver := &DNSSECIterativeResolver{validator: &dnssecValidatorStub{}}
	msg := dnssecReply("missing.example.test.", dns.TypeA)
	msg.Rcode = dns.RcodeNameError
	msg.Authoritative = true
	msg.Ns = []dns.RR{&dns.NSEC{
		Hdr:        dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "zzz.example.test.",
	}}

	_, err := resolver.validateAuthenticatedDenial(msg, msg.Question[0], []*dns.DNSKEY{authenticatedTestKey("example.test.")})
	require.ErrorContains(t, err, "has no RRSIG")
}

func nsec3Record(ownerHash, nextHash, zone string, bitmap []uint16) *dns.NSEC3 {
	return &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: strings.ToUpper(ownerHash) + "." + dns.Fqdn(zone), Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations: 0,
		SaltLength: 0,
		Salt:       "",
		HashLength: 20,
		NextDomain: strings.ToUpper(nextHash),
		TypeBitMap: bitmap,
	}
}

func TestAuthenticatedDenialNSEC3NODATA(t *testing.T) {
	resolver := &DNSSECIterativeResolver{validator: &dnssecValidatorStub{}}
	zone := "example.test."
	name := "host.example.test."
	hash := dns.HashName(name, dns.SHA1, 0, "")
	record := nsec3Record(hash, strings.Repeat("V", 32), zone, []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC3})
	msg := dnssecReply(name, dns.TypeAAAA)
	msg.Authoritative = true
	msg.Ns = []dns.RR{record, denialSignature(record.Hdr.Name, dns.TypeNSEC3, zone)}

	status, err := resolver.validateAuthenticatedDenial(msg, msg.Question[0], []*dns.DNSKEY{authenticatedTestKey(zone)})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)
}

func TestAuthenticatedDenialNSEC3NXDOMAIN(t *testing.T) {
	resolver := &DNSSECIterativeResolver{validator: &dnssecValidatorStub{}}
	zone := "example.test."
	qname := "missing.example.test."
	closestHash := dns.HashName(zone, dns.SHA1, 0, "")
	match := nsec3Record(closestHash, strings.Repeat("V", 32), zone, []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC3})
	cover := nsec3Record(strings.Repeat("0", 32), strings.Repeat("V", 32), zone, nil)
	msg := dnssecReply(qname, dns.TypeA)
	msg.Rcode = dns.RcodeNameError
	msg.Authoritative = true
	msg.Ns = []dns.RR{
		match,
		denialSignature(match.Hdr.Name, dns.TypeNSEC3, zone),
		cover,
		denialSignature(cover.Hdr.Name, dns.TypeNSEC3, zone),
	}

	status, err := resolver.validateAuthenticatedDenial(msg, msg.Question[0], []*dns.DNSKEY{authenticatedTestKey(zone)})
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, status)
}

func TestAuthenticatedDenialNSEC3OptOutFailsClosed(t *testing.T) {
	resolver := &DNSSECIterativeResolver{validator: &dnssecValidatorStub{}}
	zone := "example.test."
	hash := dns.HashName(zone, dns.SHA1, 0, "")
	record := nsec3Record(hash, strings.Repeat("V", 32), zone, nil)
	record.Flags = 1
	msg := dnssecReply("missing.example.test.", dns.TypeA)
	msg.Rcode = dns.RcodeNameError
	msg.Authoritative = true
	msg.Ns = []dns.RR{record, denialSignature(record.Hdr.Name, dns.TypeNSEC3, zone)}

	_, err := resolver.validateAuthenticatedDenial(msg, msg.Question[0], []*dns.DNSKEY{authenticatedTestKey(zone)})
	require.ErrorContains(t, err, "opt-out")
}

func TestDNSSECIterativeResolverAcceptsAuthenticatedNSECNXDOMAIN(t *testing.T) {
	rootTarget := ResolverTarget{ID: "root", Address: "192.0.2.1:53"}
	rootDNSKEY := dnssecReply(".", dns.TypeDNSKEY)
	nxdomain := dnssecReply("missing.", dns.TypeA)
	nxdomain.Rcode = dns.RcodeNameError
	nxdomain.Authoritative = true
	nxdomain.Ns = []dns.RR{
		&dns.NSEC{
			Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 60},
			NextDomain: "zzz.",
			TypeBitMap: []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
		},
		denialSignature(".", dns.TypeNSEC, "."),
		&dns.SOA{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "a.root-servers.net.", Mbox: "hostmaster.root.", Minttl: 30},
		denialSignature(".", dns.TypeSOA, "."),
	}

	executor := &dnssecScriptedResolver{responses: map[string]*dns.Msg{
		"root|.|DNSKEY":    rootDNSKEY,
		"root|missing.|A": nxdomain,
	}}
	scheduler, err := NewResolverScheduler(ResolverSchedulerConfig{MaxParallel: 1, AttemptTimeout: time.Second}, executor, []ResolverTarget{rootTarget})
	require.NoError(t, err)
	validator := &dnssecValidatorStub{rootKeys: []*dns.DNSKEY{authenticatedTestKey(".")}}
	resolver, err := NewDNSSECIterativeResolver(IterativeResolverConfig{MaxDepth: 4}, scheduler, []ResolverTarget{rootTarget}, validator, DefaultRootTrustAnchors())
	require.NoError(t, err)

	res, err := resolver.Resolve(context.Background(), iterativeQuery("missing.", dns.TypeA))
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, res.DNSSECStatus)
	require.Equal(t, 30*time.Second, res.CacheTTL)
	require.GreaterOrEqual(t, validator.rrsetCalls, 2)
}
