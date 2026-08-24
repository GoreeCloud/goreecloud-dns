package gcdns

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestBuildReferralPlanRejectsMalformedInDomainGlueAddress(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("www.example.test.", dns.TypeA)
	reply := new(dns.Msg)
	reply.SetReply(q)
	reply.Ns = []dns.RR{&dns.NS{
		Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
		Ns:  "ns1.example.test.",
	}}
	reply.Extra = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "ns1.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.IP{192, 0, 2},
	}}
	plan, err := buildReferralPlan(reply, "www.example.test.")
	require.NoError(t, err)
	require.Empty(t, plan.servers)
	require.Equal(t, []string{"ns1.example.test."}, plan.missingInDomainNS)
}

func TestCompleteReferralServersContinuesAfterExternalLookupFailure(t *testing.T) {
	plan := &referralPlan{
		zone:             "example.test.",
		outOfBailiwickNS: []string{"a.bad.test.", "b.good.test."},
	}
	resolve := func(_ context.Context, req *Request, _ *resolutionState) (*Result, error) {
		q := req.Message.Question[0]
		if dns.CanonicalName(q.Name) == "a.bad.test." {
			return nil, errors.New("simulated broken nameserver hostname")
		}
		msg := new(dns.Msg)
		msg.SetReply(req.Message)
		msg.Authoritative = true
		if dns.CanonicalName(q.Name) == "b.good.test." && q.Qtype == dns.TypeA {
			msg.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 90}}}
		}
		return &Result{Message: msg}, nil
	}
	servers, err := completeReferralServers(context.Background(), testRequest(), plan, newResolutionState(), resolve)
	require.NoError(t, err)
	require.Equal(t, []string{"192.0.2.90:53"}, servers)
}

func TestResolvedAddressEndpointsRejectsMalformedAddress(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "ns.external.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.IP{192, 0, 2},
	}}
	require.Empty(t, resolvedAddressEndpoints(msg, "ns.external.test.", dns.TypeA))
}
