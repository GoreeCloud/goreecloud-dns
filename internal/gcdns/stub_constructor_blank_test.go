package gcdns

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDelegatingStubResolverRejectsBlankZone(t *testing.T) {
	_, err := NewDelegatingStubResolver(exchangeFunc(func(context.Context, string, *dns.Msg) (*dns.Msg, error) {
		return nil, nil
	}), "   ", []string{"192.0.2.20:53"}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.ErrorContains(t, err, "zone must not be blank")
}
