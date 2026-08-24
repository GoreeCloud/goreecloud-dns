package gcdns

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestRuntimeValidationRejectsValidatingStubRootSelfTarget(t *testing.T) {
	zone := "corp.internal."
	anchor, _ := routedTrustAnchorKey(t, zone, dns.ZONE|dns.SEP)
	resolver, err := NewValidatingDelegatingStubResolver(exchangeFunc(func(context.Context, string, *dns.Msg) (*dns.Msg, error) {
		t.Fatal("runtime validation must fail before DNS exchange")
		return nil, nil
	}), zone, []string{"192.0.2.10:53"}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1}, PrivateDNSKEYTrustAnchor{Zone: zone, Keys: []*dns.DNSKEY{anchor}}, NewDNSSECValidator(nil))
	require.NoError(t, err)
	routes := []ResolverRoute{{Name: "validating-private-stub", Suffix: zone, Mode: RouteStub, Resolver: resolver}}
	_, err = NewRuntimeValidatedRoutingResolver(runtimeValidationDefaultResolver(), routes, []string{"0.0.0.0:53"}, []netip.Addr{netip.MustParseAddr("192.0.2.10")})
	require.ErrorContains(t, err, "points back to an active GoreeCloud DNS listener")
}

func TestRuntimeValidationAttachesBoundaryToValidatingStub(t *testing.T) {
	zone := "corp.internal."
	anchor, _ := routedTrustAnchorKey(t, zone, dns.ZONE|dns.SEP)
	resolver, err := NewValidatingDelegatingStubResolver(exchangeFunc(func(context.Context, string, *dns.Msg) (*dns.Msg, error) {
		return nil, nil
	}), zone, []string{"198.51.100.20:53"}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1}, PrivateDNSKEYTrustAnchor{Zone: zone, Keys: []*dns.DNSKEY{anchor}}, NewDNSSECValidator(nil))
	require.NoError(t, err)
	routes := []ResolverRoute{{Name: "validating-private-stub", Suffix: zone, Mode: RouteStub, Resolver: resolver}}
	router, err := NewRuntimeValidatedRoutingResolver(runtimeValidationDefaultResolver(), routes, []string{"0.0.0.0:53"}, []netip.Addr{netip.MustParseAddr("192.0.2.10")})
	require.NoError(t, err)
	validated, ok := router.routes[0].Resolver.(*ValidatingDelegatingStubResolver)
	require.True(t, ok)
	require.NotNil(t, validated.runtimeBoundary)
}

func TestValidatingDelegatingStubResolverRejectsQuestionOutsideZone(t *testing.T) {
	zone := "corp.internal."
	anchor, _ := routedTrustAnchorKey(t, zone, dns.ZONE|dns.SEP)
	resolver, err := NewValidatingDelegatingStubResolver(exchangeFunc(func(context.Context, string, *dns.Msg) (*dns.Msg, error) {
		t.Fatal("out-of-zone request must fail before DNS exchange")
		return nil, nil
	}), zone, []string{"198.51.100.20:53"}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1}, PrivateDNSKEYTrustAnchor{Zone: zone, Keys: []*dns.DNSKEY{anchor}}, NewDNSSECValidator(nil))
	require.NoError(t, err)
	req := testRequest()
	req.Message.SetQuestion("www.example.test.", dns.TypeA)
	_, err = resolver.Resolve(context.Background(), req)
	require.ErrorContains(t, err, "does not contain question")
}

func TestValidatingDelegatingStubResolverRejectsBlankZone(t *testing.T) {
	anchor, _ := routedTrustAnchorKey(t, ".", dns.ZONE|dns.SEP)
	_, err := NewValidatingDelegatingStubResolver(exchangeFunc(func(context.Context, string, *dns.Msg) (*dns.Msg, error) {
		return nil, nil
	}), "   ", []string{"198.51.100.20:53"}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1}, PrivateDNSKEYTrustAnchor{Zone: ".", Keys: []*dns.DNSKEY{anchor}}, NewDNSSECValidator(nil))
	require.ErrorContains(t, err, "zone must not be blank")
}
