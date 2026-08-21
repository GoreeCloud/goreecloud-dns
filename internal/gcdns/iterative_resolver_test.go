package gcdns

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type scriptedIterativeTargetResolver struct {
	mu        sync.Mutex
	responses map[string]*dns.Msg
	errors    map[string]error
	requests  map[string][]*dns.Msg
}

func (s *scriptedIterativeTargetResolver) ResolveTarget(_ context.Context, req *Request, target ResolverTarget) (*Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.requests == nil {
		s.requests = make(map[string][]*dns.Msg)
	}
	s.requests[target.ID] = append(s.requests[target.ID], req.Message.Copy())
	if err := s.errors[target.ID]; err != nil {
		return nil, err
	}
	msg := s.responses[target.ID]
	if msg == nil {
		return nil, errors.New("missing scripted response")
	}
	return &Result{Message: msg.Copy(), Source: target.ID}, nil
}

func iterativeQuery(name string, qtype uint16) *Request {
	msg := new(dns.Msg)
	msg.SetQuestion(name, qtype)
	msg.RecursionDesired = true
	return &Request{Message: msg, Transport: TransportDNS}
}

func referralResponse(query *dns.Msg, zone, nsName, glue string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(query)
	msg.RecursionAvailable = false
	msg.Authoritative = false
	msg.Answer = nil
	msg.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: nsName}}
	msg.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: nsName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}, A: []byte{192, 0, 2, 53}}}
	if glue != "" {
		msg.Extra[0].(*dns.A).A = netParseIPForTest(glue)
	}
	return msg
}

func netParseIPForTest(value string) []byte {
	parts := map[string][]byte{
		"192.0.2.53": {192, 0, 2, 53},
		"192.0.2.54": {192, 0, 2, 54},
	}
	return parts[value]
}

func TestIterativeResolverFollowsReferralAndReturnsAnswer(t *testing.T) {
	req := iterativeQuery("www.example.test.", dns.TypeA)
	rootReply := referralResponse(req.Message, "test.", "ns.test.", "192.0.2.53")
	final := new(dns.Msg)
	final.SetReply(req.Message)
	final.Authoritative = true
	final.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
		A:   []byte{203, 0, 113, 10},
	}}

	executor := &scriptedIterativeTargetResolver{responses: map[string]*dns.Msg{
		"root":                 rootReply,
		"ns.test./192.0.2.53": final,
	}, errors: map[string]error{}}
	scheduler, err := NewResolverScheduler(ResolverSchedulerConfig{MaxParallel: 1, AttemptTimeout: time.Second}, executor, []ResolverTarget{{ID: "root", Address: "192.0.2.1:53"}})
	require.NoError(t, err)
	resolver, err := NewIterativeResolver(IterativeResolverConfig{MaxDepth: 8}, scheduler, []ResolverTarget{{ID: "root", Address: "192.0.2.1:53"}})
	require.NoError(t, err)

	res, err := resolver.Resolve(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, res.Message.Answer, 1)
	require.Equal(t, 120*time.Second, res.CacheTTL)
	require.False(t, executor.requests["root"][0].RecursionDesired)
	require.False(t, executor.requests["ns.test./192.0.2.53"][0].RecursionDesired)
}

func TestReferralTargetsAcceptsInBailiwickIPv4AndIPv6Glue(t *testing.T) {
	req := iterativeQuery("www.example.test.", dns.TypeA)
	msg := new(dns.Msg)
	msg.SetReply(req.Message)
	msg.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: "ns1.example.test."},
		&dns.NS{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: "ns2.example.test."},
	}
	msg.Extra = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "ns1.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}, A: []byte{192, 0, 2, 53}},
		&dns.AAAA{Hdr: dns.RR_Header{Name: "ns2.example.test.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600}, AAAA: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53}},
	}

	zone, targets, err := referralTargets(msg, "www.example.test.")
	require.NoError(t, err)
	require.Equal(t, "example.test.", zone)
	require.Len(t, targets, 2)
	require.Equal(t, "192.0.2.53:53", targets[0].Address)
	require.Equal(t, "[2001:db8::53]:53", targets[1].Address)
}

func TestReferralTargetsRejectsOutOfBailiwickGlue(t *testing.T) {
	req := iterativeQuery("www.example.test.", dns.TypeA)
	msg := new(dns.Msg)
	msg.SetReply(req.Message)
	msg.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: "ns.external.test."}}
	msg.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ns.external.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}, A: []byte{192, 0, 2, 54}}}

	_, _, err := referralTargets(msg, "www.example.test.")
	require.ErrorContains(t, err, "no usable in-bailiwick glue")
}

func TestIterativeResolverDetectsDelegationLoop(t *testing.T) {
	req := iterativeQuery("www.example.test.", dns.TypeA)
	loop := referralResponse(req.Message, "test.", "ns.test.", "192.0.2.53")
	executor := &scriptedIterativeTargetResolver{responses: map[string]*dns.Msg{
		"root":                 loop,
		"ns.test./192.0.2.53": loop,
	}, errors: map[string]error{}}
	scheduler, err := NewResolverScheduler(ResolverSchedulerConfig{MaxParallel: 1, AttemptTimeout: time.Second}, executor, []ResolverTarget{{ID: "root", Address: "192.0.2.1:53"}})
	require.NoError(t, err)
	resolver, err := NewIterativeResolver(IterativeResolverConfig{MaxDepth: 8}, scheduler, []ResolverTarget{{ID: "root", Address: "192.0.2.1:53"}})
	require.NoError(t, err)

	_, err = resolver.Resolve(context.Background(), req)
	require.ErrorContains(t, err, "delegation loop")
}

func TestResponseCacheTTLUsesNegativeSOAMinimum(t *testing.T) {
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = []dns.RR{&dns.SOA{
		Hdr:    dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 600},
		Ns:     "ns.example.test.",
		Mbox:   "hostmaster.example.test.",
		Minttl: 90,
	}}
	require.Equal(t, 90*time.Second, responseCacheTTL(msg))
}

func TestDefaultRootTargetsIncludesCurrentBRootAddresses(t *testing.T) {
	targets := DefaultRootTargets()
	require.Len(t, targets, 26)
	addresses := make(map[string]bool, len(targets))
	for _, target := range targets {
		addresses[target.Address] = true
	}
	require.True(t, addresses["170.247.170.2:53"])
	require.True(t, addresses["[2801:1b8:10::b]:53"])
}
