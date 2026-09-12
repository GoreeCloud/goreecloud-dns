package gcdns

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type fakeTargetResolver struct {
	mu       sync.Mutex
	delays   map[string]time.Duration
	errors   map[string]error
	started  []string
	finished []string
}

func (f *fakeTargetResolver) ResolveTarget(ctx context.Context, req *Request, target ResolverTarget) (*Result, error) {
	f.mu.Lock()
	f.started = append(f.started, target.ID)
	delay := f.delays[target.ID]
	err := f.errors[target.ID]
	f.mu.Unlock()

	select {
	case <-time.After(delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	f.mu.Lock()
	f.finished = append(f.finished, target.ID)
	f.mu.Unlock()

	if err != nil {
		return nil, err
	}

	msg := new(dns.Msg)
	msg.SetReply(req.Message)
	return &Result{Message: msg, Source: target.ID, CacheTTL: time.Minute}, nil
}

func schedulerRequest() *Request {
	msg := new(dns.Msg)
	msg.SetQuestion("example.test.", dns.TypeA)
	return &Request{Message: msg, Transport: TransportDNS}
}

func TestResolverSchedulerReturnsFirstSuccessfulTarget(t *testing.T) {
	executor := &fakeTargetResolver{
		delays: map[string]time.Duration{
			"slow": 80 * time.Millisecond,
			"fast": 5 * time.Millisecond,
		},
		errors: map[string]error{},
	}
	scheduler, err := NewResolverScheduler(
		ResolverSchedulerConfig{MaxParallel: 2, AttemptTimeout: time.Second},
		executor,
		[]ResolverTarget{{ID: "slow"}, {ID: "fast"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	res, err := scheduler.Resolve(context.Background(), schedulerRequest())
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "fast" {
		t.Fatalf("expected fast target, got %q", res.Source)
	}
}

func TestResolverSchedulerFallsBackAfterFailure(t *testing.T) {
	executor := &fakeTargetResolver{
		delays: map[string]time.Duration{"bad": time.Millisecond, "good": 5 * time.Millisecond},
		errors: map[string]error{"bad": errors.New("upstream failed")},
	}
	scheduler, err := NewResolverScheduler(
		ResolverSchedulerConfig{MaxParallel: 2, AttemptTimeout: time.Second},
		executor,
		[]ResolverTarget{{ID: "bad"}, {ID: "good"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	res, err := scheduler.Resolve(context.Background(), schedulerRequest())
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "good" {
		t.Fatalf("expected fallback target, got %q", res.Source)
	}

	stats := scheduler.Stats()
	if stats["bad"].Failures == 0 {
		t.Fatal("expected failed target accounting")
	}
	if stats["good"].Successes == 0 {
		t.Fatal("expected successful target accounting")
	}
}

func TestResolverSchedulerHonorsAttemptTimeout(t *testing.T) {
	executor := &fakeTargetResolver{
		delays: map[string]time.Duration{"slow": 250 * time.Millisecond},
		errors: map[string]error{},
	}
	scheduler, err := NewResolverScheduler(
		ResolverSchedulerConfig{MaxParallel: 1, AttemptTimeout: 10 * time.Millisecond},
		executor,
		[]ResolverTarget{{ID: "slow"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = scheduler.Resolve(context.Background(), schedulerRequest())
	if err == nil {
		t.Fatal("expected timeout failure")
	}
	if scheduler.Stats()["slow"].Failures == 0 {
		t.Fatal("expected timeout to count as target failure")
	}
}

func TestResolverSchedulerValidation(t *testing.T) {
	executor := &fakeTargetResolver{delays: map[string]time.Duration{}, errors: map[string]error{}}
	cases := []struct {
		name    string
		conf    ResolverSchedulerConfig
		targets []ResolverTarget
	}{
		{name: "parallel", conf: ResolverSchedulerConfig{AttemptTimeout: time.Second}, targets: []ResolverTarget{{ID: "a"}}},
		{name: "timeout", conf: ResolverSchedulerConfig{MaxParallel: 1}, targets: []ResolverTarget{{ID: "a"}}},
		{name: "targets", conf: ResolverSchedulerConfig{MaxParallel: 1, AttemptTimeout: time.Second}},
		{name: "empty id", conf: ResolverSchedulerConfig{MaxParallel: 1, AttemptTimeout: time.Second}, targets: []ResolverTarget{{ID: ""}}},
		{name: "duplicate", conf: ResolverSchedulerConfig{MaxParallel: 1, AttemptTimeout: time.Second}, targets: []ResolverTarget{{ID: "a"}, {ID: "a"}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewResolverScheduler(tc.conf, executor, tc.targets); err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}
}
