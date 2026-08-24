package gcdns

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func schedulerResult(source string) *Result {
	m := new(dns.Msg)
	m.SetReply(testRequest().Message)
	return &Result{Message: m, Source: source}
}

func TestTargetSchedulerFailsOver(t *testing.T) {
	var first, second atomic.Int64
	s, err := NewTargetScheduler([]ResolverTarget{
		{Name: "broken", Resolver: resolverFunc(func(context.Context, *Request) (*Result, error) { first.Add(1); return nil, errors.New("broken") })},
		{Name: "healthy", Resolver: resolverFunc(func(context.Context, *Request) (*Result, error) {
			second.Add(1)
			return schedulerResult("healthy"), nil
		})},
	}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 4})
	require.NoError(t, err)

	res, err := s.Resolve(context.Background(), testRequest())
	require.NoError(t, err)
	require.Equal(t, "healthy", res.Source)
	require.EqualValues(t, 1, first.Load())
	require.EqualValues(t, 1, second.Load())
}

func TestTargetSchedulerHonorsAttemptTimeout(t *testing.T) {
	s, err := NewTargetScheduler([]ResolverTarget{{Name: "slow", Resolver: resolverFunc(func(ctx context.Context, _ *Request) (*Result, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})}}, SchedulerConfig{AttemptTimeout: 5 * time.Millisecond, MaxConcurrent: 1})
	require.NoError(t, err)

	_, err = s.Resolve(context.Background(), testRequest())
	require.ErrorIs(t, err, context.DeadlineExceeded)
	stats := s.Stats()
	require.EqualValues(t, 1, stats[0].Attempts)
	require.EqualValues(t, 1, stats[0].Failures)
	require.EqualValues(t, 1, stats[0].Timeouts)
}

func TestTargetSchedulerPrefersSuccessfulTarget(t *testing.T) {
	var badCalls, goodCalls atomic.Int64
	bad := resolverFunc(func(context.Context, *Request) (*Result, error) { badCalls.Add(1); return nil, errors.New("bad") })
	good := resolverFunc(func(context.Context, *Request) (*Result, error) {
		goodCalls.Add(1)
		return schedulerResult("good"), nil
	})
	s, err := NewTargetScheduler([]ResolverTarget{{Name: "bad", Resolver: bad}, {Name: "good", Resolver: good}}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 2})
	require.NoError(t, err)

	_, err = s.Resolve(context.Background(), testRequest())
	require.NoError(t, err)
	_, err = s.Resolve(context.Background(), testRequest())
	require.NoError(t, err)
	require.EqualValues(t, 1, badCalls.Load(), "successful target should move ahead after health evidence")
	require.EqualValues(t, 2, goodCalls.Load())
}

func TestTargetSchedulerPropagatesCallerCancellation(t *testing.T) {
	s, err := NewTargetScheduler([]ResolverTarget{{Name: "target", Resolver: resolverFunc(func(context.Context, *Request) (*Result, error) { return schedulerResult("target"), nil })}}, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.Resolve(ctx, testRequest())
	require.ErrorIs(t, err, context.Canceled)
}

func TestTargetSchedulerValidatesConfiguration(t *testing.T) {
	_, err := NewTargetScheduler(nil, SchedulerConfig{AttemptTimeout: time.Second, MaxConcurrent: 1})
	require.Error(t, err)
	_, err = NewTargetScheduler([]ResolverTarget{{Name: "x", Resolver: resolverFunc(func(context.Context, *Request) (*Result, error) { return nil, nil })}}, SchedulerConfig{MaxConcurrent: 1})
	require.Error(t, err)
	_, err = NewTargetScheduler([]ResolverTarget{{Name: "x", Resolver: resolverFunc(func(context.Context, *Request) (*Result, error) { return nil, nil })}}, SchedulerConfig{AttemptTimeout: time.Second})
	require.Error(t, err)
}
