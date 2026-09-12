package gcdns

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestValidatingStubRejectsDynamicChildSelfTarget(t *testing.T) {
	zone := "corp.internal."
	childZone := "branch.corp.internal."
	qname := "host.branch.corp.internal."
	rootServer := "198.51.100.20:53"
	parentKSK, parentKSKSigner := routedTrustAnchorKey(t, zone, dns.ZONE|dns.SEP)
	parentZSK, parentZSKSigner := routedTrustAnchorKey(t, zone, dns.ZONE)
	parentDNSKEYSig := signRoutedTrustAnchorRRSet(t, []dns.RR{parentKSK, parentZSK}, parentKSK, parentKSKSigner)
	childKSK, _ := routedTrustAnchorKey(t, childZone, dns.ZONE|dns.SEP)
	childDS := childKSK.ToDS(dns.SHA256)
	require.NotNil(t, childDS)
	childDSSig := signRoutedTrustAnchorRRSet(t, []dns.RR{childDS}, parentZSK, parentZSKSigner)

	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		require.Equal(t, rootServer, server)
		reply := new(dns.Msg)
		reply.SetReply(query)
		q := query.Question[0]
		if q.Qtype == dns.TypeDNSKEY && equalName(q.Name, zone) {
			reply.Authoritative = true
			reply.Answer = []dns.RR{parentKSK, parentZSK, parentDNSKEYSig}
			return reply, nil
		}
		reply.Ns = []dns.RR{
			&dns.NS{Hdr: dns.RR_Header{Name: childZone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns." + childZone},
			childDS,
			childDSSig,
		}
		reply.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns." + childZone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 10}}}
		return reply, nil
	})

	resolver, err := NewValidatingDelegatingStubResolver(exchanger, zone, []string{rootServer}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1}, PrivateDNSKEYTrustAnchor{Zone: zone, Keys: []*dns.DNSKEY{parentKSK}}, NewDNSSECValidator(func() time.Time { return nsec3TestNow }))
	require.NoError(t, err)
	router, err := NewRuntimeValidatedRoutingResolver(runtimeValidationDefaultResolver(), []ResolverRoute{{Name: "validated-private", Suffix: zone, Mode: RouteStub, Resolver: resolver}}, []string{"0.0.0.0:53"}, []netip.Addr{netip.MustParseAddr("192.0.2.10")})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion(qname, dns.TypeA)
	_, err = router.Resolve(context.Background(), req)
	require.ErrorContains(t, err, "points back to an active GoreeCloud DNS listener")
}
