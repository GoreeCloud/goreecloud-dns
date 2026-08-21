package gcdns

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type rcodeTargetResolver struct {
	mu     sync.Mutex
	rcodes map[string]int
}

func (r *rcodeTargetResolver) ResolveTarget(_ context.Context, req *Request, target ResolverTarget) (*Result, error) {
	r.mu.Lock()
	rcode := r.rcodes[target.ID]
	r.mu.Unlock()

	msg := new(dns.Msg)
	msg.SetReply(req.Message)
	msg.Rcode = rcode
	return &Result{Message: msg, Source: target.ID}, nil
}

func TestResolverSchedulerFailsOverRetryableResponseCodes(t *testing.T) {
	for _, rcode := range []int{dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeNotImplemented, dns.RcodeFormatError} {
		t.Run(dns.RcodeToString[rcode], func(t *testing.T) {
			executor := &rcodeTargetResolver{rcodes: map[string]int{"bad": rcode, "good": dns.RcodeSuccess}}
			scheduler, err := NewResolverScheduler(
				ResolverSchedulerConfig{MaxParallel: 2, AttemptTimeout: time.Second},
				executor,
				[]ResolverTarget{{ID: "bad"}, {ID: "good"}},
			)
			require.NoError(t, err)

			res, err := scheduler.Resolve(context.Background(), schedulerRequest())
			require.NoError(t, err)
			require.Equal(t, "good", res.Source)
			require.Equal(t, uint64(1), scheduler.Stats()["bad"].Failures)
		})
	}
}

func TestResolverSchedulerAcceptsNXDOMAIN(t *testing.T) {
	executor := &rcodeTargetResolver{rcodes: map[string]int{"nxdomain": dns.RcodeNameError}}
	scheduler, err := NewResolverScheduler(
		ResolverSchedulerConfig{MaxParallel: 1, AttemptTimeout: time.Second},
		executor,
		[]ResolverTarget{{ID: "nxdomain"}},
	)
	require.NoError(t, err)

	res, err := scheduler.Resolve(context.Background(), schedulerRequest())
	require.NoError(t, err)
	require.Equal(t, dns.RcodeNameError, res.Message.Rcode)
	require.Equal(t, uint64(1), scheduler.Stats()["nxdomain"].Successes)
}
