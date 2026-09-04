package gcdns

import (
	"context"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ResolverTarget is one independently callable upstream or recursive target.
type ResolverTarget struct {
	Name     string
	Resolver Resolver
}

// SchedulerConfig controls Beacon resolver target selection and failover.
type SchedulerConfig struct {
	AttemptTimeout time.Duration
	MaxConcurrent  int
	Now            func() time.Time
}

// TargetStats is a privacy-safe snapshot of target health.
type TargetStats struct {
	Name           string
	Attempts       uint64
	Successes      uint64
	Failures       uint64
	Timeouts       uint64
	InFlight       int64
	AverageLatency time.Duration
}

type targetState struct {
	target       ResolverTarget
	attempts     atomic.Uint64
	successes    atomic.Uint64
	failures     atomic.Uint64
	timeouts     atomic.Uint64
	inflight     atomic.Int64
	latencyNanos atomic.Uint64
}

// TargetScheduler selects healthy low-latency targets and performs bounded
// sequential failover.  It intentionally does not expose query names in stats.
type TargetScheduler struct {
	targets []*targetState
	timeout time.Duration
	sem     chan struct{}
	now     func() time.Time
}

func NewTargetScheduler(targets []ResolverTarget, cfg SchedulerConfig) (*TargetScheduler, error) {
	if len(targets) == 0 {
		return nil, errors.New("goreecloud dns: resolver scheduler requires at least one target")
	}
	if cfg.AttemptTimeout <= 0 {
		return nil, errors.New("goreecloud dns: resolver attempt timeout must be positive")
	}
	if cfg.MaxConcurrent <= 0 {
		return nil, errors.New("goreecloud dns: resolver max concurrency must be positive")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	s := &TargetScheduler{timeout: cfg.AttemptTimeout, sem: make(chan struct{}, cfg.MaxConcurrent), now: cfg.Now}
	seen := map[string]struct{}{}
	for _, target := range targets {
		if target.Name == "" || target.Resolver == nil {
			return nil, errors.New("goreecloud dns: resolver targets require name and resolver")
		}
		if _, ok := seen[target.Name]; ok {
			return nil, errors.New("goreecloud dns: resolver target names must be unique")
		}
		seen[target.Name] = struct{}{}
		s.targets = append(s.targets, &targetState{target: target})
	}
	return s, nil
}

// Resolve tries targets in health/latency order until one succeeds.
func (s *TargetScheduler) Resolve(ctx context.Context, req *Request) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ordered := s.orderedTargets()
	var errs []error
	for _, target := range ordered {
		select {
		case s.sem <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		res, err := s.attempt(ctx, target, req)
		<-s.sem
		if err == nil && res != nil {
			return res, nil
		}
		if err == nil {
			err = errors.New("goreecloud dns: resolver target returned nil result")
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func (s *TargetScheduler) attempt(ctx context.Context, state *targetState, req *Request) (*Result, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	state.attempts.Add(1)
	state.inflight.Add(1)
	defer state.inflight.Add(-1)
	start := s.now()
	res, err := state.target.Resolver.Resolve(attemptCtx, req)
	elapsed := s.now().Sub(start)
	if elapsed > 0 {
		state.latencyNanos.Add(uint64(elapsed))
	}
	if err != nil {
		state.failures.Add(1)
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(attemptCtx.Err(), context.DeadlineExceeded) {
			state.timeouts.Add(1)
		}
		return nil, err
	}
	if res == nil {
		state.failures.Add(1)
		return nil, errors.New("goreecloud dns: resolver target returned nil result")
	}
	state.successes.Add(1)
	return res, nil
}

func (s *TargetScheduler) orderedTargets() []*targetState {
	ordered := append([]*targetState(nil), s.targets...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		aSuccess, bSuccess := a.successes.Load(), b.successes.Load()
		aFail, bFail := a.failures.Load(), b.failures.Load()
		if aSuccess+aFail == 0 && bSuccess+bFail != 0 {
			return false
		}
		if bSuccess+bFail == 0 && aSuccess+aFail != 0 {
			return true
		}
		aRate := float64(aSuccess) / float64(max64(1, aSuccess+aFail))
		bRate := float64(bSuccess) / float64(max64(1, bSuccess+bFail))
		if aRate != bRate {
			return aRate > bRate
		}
		aLatency := averageLatency(a)
		bLatency := averageLatency(b)
		if aLatency != bLatency {
			return aLatency < bLatency
		}
		return a.target.Name < b.target.Name
	})
	return ordered
}

// Stats returns target-level health without retaining request identity or names.
func (s *TargetScheduler) Stats() []TargetStats {
	stats := make([]TargetStats, 0, len(s.targets))
	for _, state := range s.targets {
		stats = append(stats, TargetStats{Name: state.target.Name, Attempts: state.attempts.Load(), Successes: state.successes.Load(), Failures: state.failures.Load(), Timeouts: state.timeouts.Load(), InFlight: state.inflight.Load(), AverageLatency: averageLatency(state)})
	}
	return stats
}

func averageLatency(s *targetState) time.Duration {
	attempts := s.attempts.Load()
	if attempts == 0 {
		return 0
	}
	return time.Duration(s.latencyNanos.Load() / attempts)
}

func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

var (
	_ Resolver    = (*TargetScheduler)(nil)
	_ sync.Locker = (*sync.Mutex)(nil)
)
