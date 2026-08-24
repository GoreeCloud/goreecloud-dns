package gcdns

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDelegatingStubResolverEnforcesDelegationDepth(t *testing.T) {
	const root = "192.0.2.20:53"
	zones := make([]string, maxStubDelegationDepth)
	servers := make([]string, maxStubDelegationDepth+1)
	servers[0] = root
	zone := "corp.internal."
	for i := 0; i < maxStubDelegationDepth; i++ {
		zone = fmt.Sprintf("z%d.%s", i+1, zone)
		zones[i] = zone
		servers[i+1] = fmt.Sprintf("192.0.2.%d:53", 21+i)
	}
	qname := "host." + zones[len(zones)-1]

	exchanger := exchangeFunc(func(_ context.Context, server string, query *dns.Msg) (*dns.Msg, error) {
		var index int
		for i, candidate := range servers {
			if candidate == server {
				index = i
				break
			}
		if index >= len(zones) {
			reply := new(dns.Msg)
			reply.SetReply(query)
			reply.Authoritative = true
			return reply, nil
		}
		nsHost := "ns." + zones[index]
		return stubReferralReply(query, zones[index], nsHost, &dns.A{
			Hdr: dns.RR_Header{Name: nsHost, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{192, 0, 2, byte(21 + index)},
		}), nil
	})
	resolver, err := NewDelegatingStubResolver(exchanger, "corp.internal.", []string{root}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion(qname, dns.TypeA)
	_, err = resolver.Resolve(context.Background(), req)
	require.ErrorContains(t, err, "stub delegation depth exceeded")
}

func TestValidateRoutingRuntimeRejectsDelegatingStubSelfTarget(t *testing.T) {
	exchanger := exchangeFunc(func(context.Context, string, *dns.Msg) (*dns.Msg, error) {
		t.Fatal("runtime validation must not perform DNS exchanges")
		return nil, nil
	})
	stub, err := NewDelegatingStubResolver(exchanger, "corp.internal.", []string{"192.0.2.20:53"}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	route := ResolverRoute{Name: "delegating-stub", Suffix: "corp.internal.", Mode: RouteStub, Resolver: stub}
	err = ValidateRoutingRuntime([]string{"0.0.0.0:53"}, []netip.Addr{netip.MustParseAddr("192.0.2.20")}, []ResolverRoute{route})
	require.ErrorContains(t, err, "points back to an active GoreeCloud DNS listener")
}

func TestDelegatingStubResolverRejectsQuestionOutsideConfiguredZone(t *testing.T) {
	resolver, err := NewDelegatingStubResolver(exchangeFunc(func(context.Context, string, *dns.Msg) (*dns.Msg, error) {
		t.Fatal("out-of-zone question must fail before DNS exchange")
		return nil, nil
	}), "corp.internal.", []string{"192.0.2.20:53"}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("www.example.test.", dns.TypeA)
	_, err = resolver.Resolve(context.Background(), req)
	require.ErrorContains(t, err, "does not contain question")
}

func TestDelegatingStubResolverRejectsInvalidConstruction(t *testing.T) {
	_, err := NewDelegatingStubResolver(nil, "corp.internal.", []string{"192.0.2.20:53"}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.ErrorContains(t, err, "requires a DNS exchanger")
	_, err = NewDelegatingStubResolver(exchangeFunc(func(context.Context, string, *dns.Msg) (*dns.Msg, error) { return nil, nil }), "bad..zone", []string{"192.0.2.20:53"}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.Error(t, err)
	_, err = NewDelegatingStubResolver(exchangeFunc(func(context.Context, string, *dns.Msg) (*dns.Msg, error) { return nil, nil }), "corp.internal.", []string{"not-an-endpoint"}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.Error(t, err)
}

func TestDelegatingStubDepthFixtureUsesUniqueZones(t *testing.T) {
	// Guard the synthetic depth-test shape itself so a future edit cannot make
	// the referral sequence accidentally repeat a zone and test a loop instead.
	seen := map[string]struct{}{}
	zone := "corp.internal."
	for i := 0; i < maxStubDelegationDepth; i++ {
		zone = fmt.Sprintf("z%d.%s", i+1, zone)
		canonical := strings.ToLower(dns.Fqdn(zone))
		_, duplicate := seen[canonical]
		require.False(t, duplicate)
		seen[canonical] = struct{}{}
	}
}
