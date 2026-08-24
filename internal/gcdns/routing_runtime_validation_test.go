package gcdns

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func runtimeValidationForwarder(t *testing.T, server string) *ForwardingResolver {
	t.Helper()
	resolver, err := NewForwardingResolver(exchangeFunc(func(context.Context, string, *dns.Msg) (*dns.Msg, error) {
		t.Fatal("runtime validation must not perform DNS exchanges")
		return nil, nil
	}), []string{server}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	return resolver
}

func runtimeValidationStub(t *testing.T, zone, server string) *StubResolver {
	t.Helper()
	resolver, err := NewStubResolver(exchangeFunc(func(context.Context, string, *dns.Msg) (*dns.Msg, error) {
		t.Fatal("runtime validation must not perform DNS exchanges")
		return nil, nil
	}), zone, []string{server}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	return resolver
}

func TestValidateRoutingRuntimeRejectsExactForwardSelfTarget(t *testing.T) {
	route := ResolverRoute{Name: "forward", Suffix: ".", Mode: RouteForward, Resolver: runtimeValidationForwarder(t, "127.0.0.1:53")}
	err := ValidateRoutingRuntime([]string{"127.0.0.1:53"}, nil, []ResolverRoute{route})
	require.ErrorContains(t, err, "points back to an active GoreeCloud DNS listener")
}

func TestValidateRoutingRuntimeRejectsWildcardLoopbackTarget(t *testing.T) {
	route := ResolverRoute{Name: "forward", Suffix: ".", Mode: RouteForward, Resolver: runtimeValidationForwarder(t, "127.0.0.1:53")}
	err := ValidateRoutingRuntime([]string{"0.0.0.0:53"}, nil, []ResolverRoute{route})
	require.ErrorContains(t, err, "points back to an active GoreeCloud DNS listener")
}

func TestValidateRoutingRuntimeRejectsWildcardKnownLocalAddress(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.10")
	route := ResolverRoute{Name: "forward", Suffix: ".", Mode: RouteForward, Resolver: runtimeValidationForwarder(t, "192.0.2.10:53")}
	err := ValidateRoutingRuntime([]string{"0.0.0.0:53"}, []netip.Addr{local}, []ResolverRoute{route})
	require.ErrorContains(t, err, "points back to an active GoreeCloud DNS listener")
}

func TestValidateRoutingRuntimeAllowsExternalTargetOnWildcardPort(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.10")
	route := ResolverRoute{Name: "forward", Suffix: ".", Mode: RouteForward, Resolver: runtimeValidationForwarder(t, "1.1.1.1:53")}
	require.NoError(t, ValidateRoutingRuntime([]string{"0.0.0.0:53"}, []netip.Addr{local}, []ResolverRoute{route}))
}

func TestValidateRoutingRuntimeAllowsLocalAddressOnDifferentPort(t *testing.T) {
	route := ResolverRoute{Name: "forward", Suffix: ".", Mode: RouteForward, Resolver: runtimeValidationForwarder(t, "127.0.0.1:53")}
	require.NoError(t, ValidateRoutingRuntime([]string{"127.0.0.1:5353"}, nil, []ResolverRoute{route}))
}

func TestValidateRoutingRuntimeRejectsStubSelfTarget(t *testing.T) {
	route := ResolverRoute{Name: "private-stub", Suffix: "private.example.", Mode: RouteStub, Resolver: runtimeValidationStub(t, "private.example.", "192.0.2.10:53")}
	err := ValidateRoutingRuntime([]string{"192.0.2.10:53"}, []netip.Addr{netip.MustParseAddr("192.0.2.10")}, []ResolverRoute{route})
	require.ErrorContains(t, err, "points back to an active GoreeCloud DNS listener")
}

func TestValidateRoutingRuntimeRejectsIPv6WildcardLoopbackTarget(t *testing.T) {
	route := ResolverRoute{Name: "forward-v6", Suffix: ".", Mode: RouteForward, Resolver: runtimeValidationForwarder(t, "[::1]:53")}
	err := ValidateRoutingRuntime([]string{"[::]:53"}, nil, []ResolverRoute{route})
	require.ErrorContains(t, err, "points back to an active GoreeCloud DNS listener")
}

func TestValidateRoutingRuntimeRequiresNumericTargetAddress(t *testing.T) {
	route := ResolverRoute{Name: "named-forward", Suffix: ".", Mode: RouteForward, Resolver: runtimeValidationForwarder(t, "resolver.example:53")}
	err := ValidateRoutingRuntime([]string{"0.0.0.0:53"}, nil, []ResolverRoute{route})
	require.ErrorContains(t, err, "requires a numeric IP address")
}

func TestValidateRoutingRuntimeRejectsInvalidLocalAddressSnapshot(t *testing.T) {
	route := ResolverRoute{Name: "forward", Suffix: ".", Mode: RouteForward, Resolver: runtimeValidationForwarder(t, "1.1.1.1:53")}
	err := ValidateRoutingRuntime([]string{"0.0.0.0:53"}, []netip.Addr{{}}, []ResolverRoute{route})
	require.ErrorContains(t, err, "invalid address")
}

func TestValidateRoutingRuntimeRequiresListener(t *testing.T) {
	route := ResolverRoute{Name: "forward", Suffix: ".", Mode: RouteForward, Resolver: runtimeValidationForwarder(t, "1.1.1.1:53")}
	err := ValidateRoutingRuntime(nil, nil, []ResolverRoute{route})
	require.ErrorContains(t, err, "requires at least one active listener")
}
