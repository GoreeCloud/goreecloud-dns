package gcdns

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestRuntimeValidationRejectsValidatingForwarderSelfTarget(t *testing.T) {
	exchanger := exchangeFunc(func(context.Context, string, *dns.Msg) (*dns.Msg, error) {
		t.Fatal("runtime validation must not perform DNS exchange")
		return nil, nil
	})
	resolver, err := NewValidatingForwardingResolver(
		exchanger,
		[]string{"192.0.2.53:53"},
		SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1},
		NewDNSSECValidator(nil),
	)
	require.NoError(t, err)
	route := ResolverRoute{Name: "validated-forward", Suffix: ".", Mode: RouteForward, Resolver: resolver}
	err = ValidateRoutingRuntime([]string{"0.0.0.0:53"}, []netip.Addr{netip.MustParseAddr("192.0.2.53")}, []ResolverRoute{route})
	require.ErrorContains(t, err, "points back to an active GoreeCloud DNS listener")
}
