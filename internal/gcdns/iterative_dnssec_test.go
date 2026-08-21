package gcdns

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type dnssecScriptedResolver struct {
	mu        sync.Mutex
	responses map[string]*dns.Msg
	requests  []string
}

func (s *dnssecScriptedResolver) ResolveTarget(_ context.Context, req *Request, target ResolverTarget) (*Result, error) {
	if req == nil || req.Message == nil || len(req.Message.Question) != 1 {
		return nil, errors.New("invalid scripted request")
	}
	q := req.Message.Question[0]
	key := target.ID + "|" + dns.Fqdn(q.Name) + "|" + dns.TypeToString[q.Qtype]
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, key)
	msg := s.responses[key]
	if msg == nil {
		return nil, errors.New("missing scripted DNSSEC response: " + key)
	}
	return &Result{Message: msg.Copy(), Source: target.ID}, nil
}

type dnssecValidatorStub struct {
	rootCalls       int
	delegationCalls int
	rrsetCalls      int
	rootKeys        []*dns.DNSKEY
	childKeys       []*dns.DNSKEY
}

func (v *dnssecValidatorStub) ValidateRootDNSKEY(_ *dns.Msg, _ []*dns.DS) (DNSSECStatus, []*dns.DNSKEY, error) {
	v.rootCalls++
	return DNSSECSecure, v.rootKeys, nil
}

func (v *dnssecValidatorStub) ValidateSignedDelegation(_ []*dns.DNSKEY, _ *dns.Msg, _ *dns.Msg, _ string) (DNSSECStatus, []*dns.DNSKEY, error) {
	v.delegationCalls++
	return DNSSECSecure, v.childKeys, nil
}

func (v *dnssecValidatorStub) ValidateRRSet(_ []dns.RR, _ []*dns.RRSIG, _ []*dns.DNSKEY) (DNSSECStatus, error) {
	v.rrsetCalls++
	return DNSSECSecure, nil
}

func dnssecReply(queryName string, qtype uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(queryName, qtype)
	m := new(dns.Msg)
	m.SetReply(q)
	m.RecursionAvailable = false
	return m
}

func TestDNSSECIterativeResolverCarriesAuthenticatedKeysAcrossReferral(t *testing.T) {
	rootTarget := ResolverTarget{ID: "root", Address: "192.0.2.1:53"}
	childTargetID := "ns.test./192.0.2.53"

	rootDNSKEY := dnssecReply(".", dns.TypeDNSKEY)
	rootReferral := dnssecReply("www.example.test.", dns.TypeA)
	rootReferral.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: "ns.test."},
		&dns.DS{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}, KeyTag: 1, Algorithm: dns.RSASHA256, DigestType: dns.SHA256, Digest: "00"},
	}
	rootReferral.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}, A: net.ParseIP("192.0.2.53").To4()}}

	childDNSKEY := dnssecReply("test.", dns.TypeDNSKEY)
	final := dnssecReply("www.example.test.", dns.TypeA)
	final.Authoritative = true
	final.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.ParseIP("203.0.113.10").To4()},
		&dns.RRSIG{Hdr: dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 120}, TypeCovered: dns.TypeA, Algorithm: dns.RSASHA256, SignerName: "test."},
	}

	executor := &dnssecScriptedResolver{responses: map[string]*dns.Msg{
		"root|.|DNSKEY":                         rootDNSKEY,
		"root|www.example.test.|A":             rootReferral,
		childTargetID + "|test.|DNSKEY":         childDNSKEY,
		childTargetID + "|www.example.test.|A": final,
	}}
	scheduler, err := NewResolverScheduler(ResolverSchedulerConfig{MaxParallel: 1, AttemptTimeout: time.Second}, executor, []ResolverTarget{rootTarget})
	require.NoError(t, err)

	rootKey := &dns.DNSKEY{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET}, Protocol: 3}
	childKey := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET}, Protocol: 3}
	validator := &dnssecValidatorStub{rootKeys: []*dns.DNSKEY{rootKey}, childKeys: []*dns.DNSKEY{childKey}}
	resolver, err := NewDNSSECIterativeResolver(
		IterativeResolverConfig{MaxDepth: 8},
		scheduler,
		[]ResolverTarget{rootTarget},
		validator,
		DefaultRootTrustAnchors(),
	)
	require.NoError(t, err)

	res, err := resolver.Resolve(context.Background(), iterativeQuery("www.example.test.", dns.TypeA))
	require.NoError(t, err)
	require.Equal(t, DNSSECSecure, res.DNSSECStatus)
	require.Equal(t, 120*time.Second, res.CacheTTL)
	require.Equal(t, 1, validator.rootCalls)
	require.Equal(t, 1, validator.delegationCalls)
	require.Equal(t, 1, validator.rrsetCalls)
	require.Equal(t, []string{
		"root|.|DNSKEY",
		"root|www.example.test.|A",
		childTargetID + "|test.|DNSKEY",
		childTargetID + "|www.example.test.|A",
	}, executor.requests)
}

func TestDNSSECIterativeResolverFailsClosedOnNegativeWithoutDenialProof(t *testing.T) {
	rootTarget := ResolverTarget{ID: "root", Address: "192.0.2.1:53"}
	rootDNSKEY := dnssecReply(".", dns.TypeDNSKEY)
	nxdomain := dnssecReply("missing.", dns.TypeA)
	nxdomain.Rcode = dns.RcodeNameError
	nxdomain.Authoritative = true

	executor := &dnssecScriptedResolver{responses: map[string]*dns.Msg{
		"root|.|DNSKEY":    rootDNSKEY,
		"root|missing.|A": nxdomain,
	}}
	scheduler, err := NewResolverScheduler(ResolverSchedulerConfig{MaxParallel: 1, AttemptTimeout: time.Second}, executor, []ResolverTarget{rootTarget})
	require.NoError(t, err)
	validator := &dnssecValidatorStub{rootKeys: []*dns.DNSKEY{{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET}, Protocol: 3}}}
	resolver, err := NewDNSSECIterativeResolver(IterativeResolverConfig{MaxDepth: 4}, scheduler, []ResolverTarget{rootTarget}, validator, DefaultRootTrustAnchors())
	require.NoError(t, err)

	_, err = resolver.Resolve(context.Background(), iterativeQuery("missing.", dns.TypeA))
	require.ErrorContains(t, err, "authenticated denial")
}

func TestDNSSECIterativeResolverRequiresTrustInputs(t *testing.T) {
	rootTarget := ResolverTarget{ID: "root", Address: "192.0.2.1:53"}
	executor := &dnssecScriptedResolver{responses: map[string]*dns.Msg{}}
	scheduler, err := NewResolverScheduler(ResolverSchedulerConfig{MaxParallel: 1, AttemptTimeout: time.Second}, executor, []ResolverTarget{rootTarget})
	require.NoError(t, err)

	_, err = NewDNSSECIterativeResolver(IterativeResolverConfig{MaxDepth: 4}, scheduler, []ResolverTarget{rootTarget}, nil, DefaultRootTrustAnchors())
	require.ErrorContains(t, err, "requires a validator")

	_, err = NewDNSSECIterativeResolver(IterativeResolverConfig{MaxDepth: 4}, scheduler, []ResolverTarget{rootTarget}, &dnssecValidatorStub{}, nil)
	require.ErrorContains(t, err, "requires root trust anchors")
}
