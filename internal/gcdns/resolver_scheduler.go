package gcdns

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ResolverTarget identifies a recursive, forwarder, conditional-forwarder, or
// stub resolution target owned by Beacon Resolver. Address is a host:port
// endpoint used by network transports. Network is transport-specific and
// defaults to UDP for the classic DNS transport.
type ResolverTarget struct {
	ID      string
	Address string
	Network string
}

// TargetResolver executes one resolution attempt against a specific target.
// Implementations remain responsible for DNS transport, protocol validation,
// DNSSEC processing, and target-specific behavior.
type TargetResolver interface {
	ResolveTarget(ctx context.Context, req *Request, target ResolverTarget) (*Result, error)
}

// ResolverSchedulerConfig controls concurrent target selection and attempt
// lifetimes. MaxParallel and AttemptTimeout must both be positive.
type ResolverSchedulerConfig struct {
	MaxParallel    int
	AttemptTimeout time.Duration
}

// ResolverTargetStats exposes privacy-safe target health and latency data.
type ResolverTargetStats struct {
	Successes   uint64
	Failures    uint64
	LastLatency time.Duration
}

// ResolverScheduler implements Resolver with bounded concurrent attempts,
// cancellation after the first successful result, and latency-aware target
// ordering based on observed successful attempts.
type ResolverScheduler struct {
	conf     ResolverSchedulerConfig
	executor TargetResolver
	targets  []ResolverTarget

	mu    sync.RWMutex
	stats map[string]ResolverTargetStats
}

// NewResolverScheduler creates the native Beacon Resolver scheduling layer.
func NewResolverScheduler(conf ResolverSchedulerConfig, executor TargetResolver, targets []ResolverTarget) (*ResolverScheduler, error) {
	if executor == nil {
		return nil, errors.New("goreecloud dns: resolver scheduler requires an executor")
	}
	if conf.MaxParallel <= 0 {
		return nil, errors.New("goreecloud dns: resolver scheduler max parallel must be positive")
	}
	if conf.AttemptTimeout <= 0 {
		return nil, errors.New("goreecloud dns: resolver scheduler attempt timeout must be positive")
	}
	copyTargets, err := validateResolverTargets(targets)
	if err != nil {
		return nil, err
	}

	return &ResolverScheduler{
		conf:     conf,
		executor: executor,
		targets:  copyTargets,
		stats:    make(map[string]ResolverTargetStats, len(targets)),
	}, nil
}

// Resolve implements Resolver against the scheduler's configured target set.
func (s *ResolverScheduler) Resolve(parent context.Context, req *Request) (*Result, error) {
	return s.ResolveTargets(parent, req, s.targets)
}

// ResolveTargets executes one resolver step against a caller-supplied target
// set. It is used by iterative recursion when each delegation produces a new
// authoritative name-server set while preserving scheduler concurrency,
// timeout, cancellation, ordering, and health accounting.
func (s *ResolverScheduler) ResolveTargets(parent context.Context, req *Request, targets []ResolverTarget) (*Result, error) {
	if req == nil || req.Message == nil {
		return nil, errors.New("goreecloud dns: nil resolver request")
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}

	copyTargets, err := validateResolverTargets(targets)
	if err != nil {
		return nil, err
	}
	ordered := s.orderedTargets(copyTargets)
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	type attemptResult struct {
		result *Result
		err    error
	}

	results := make(chan attemptResult, len(ordered))
	sem := make(chan struct{}, s.conf.MaxParallel)
	var wg sync.WaitGroup

	for _, target := range ordered {
		target := target
		wg.Add(1)
		go func() {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			attemptCtx, attemptCancel := context.WithTimeout(ctx, s.conf.AttemptTimeout)
			started := time.Now()
			res, err := s.executor.ResolveTarget(attemptCtx, req, target)
			latency := time.Since(started)
			attemptCancel()

			if err == nil && (res == nil || res.Message == nil) {
				err = errors.New("resolver target returned nil response")
			}
			if err == nil {
				err = resolverTargetResponseError(res.Message)
			}
			s.recordAttempt(target.ID, latency, err)

			select {
			case results <- attemptResult{result: res, err: err}:
			case <-ctx.Done():
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var lastErr error
	for attempt := range results {
		if attempt.err == nil && attempt.result != nil && attempt.result.Message != nil {
			cancel()
			return attempt.result, nil
		}
		if attempt.err != nil && !errors.Is(attempt.err, context.Canceled) {
			lastErr = attempt.err
		}
		if err := parent.Err(); err != nil {
			cancel()
			return nil, err
		}
	}

	if err := parent.Err(); err != nil {
		return nil, err
	}
	if lastErr != nil {
		return nil, fmt.Errorf("goreecloud dns: all resolver targets failed: %w", lastErr)
	}
	return nil, errors.New("goreecloud dns: all resolver targets failed")
}

// Stats returns a defensive snapshot of target health data.
func (s *ResolverScheduler) Stats() map[string]ResolverTargetStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]ResolverTargetStats, len(s.stats))
	for id, stats := range s.stats {
		out[id] = stats
	}
	return out
}

func validateResolverTargets(targets []ResolverTarget) ([]ResolverTarget, error) {
	if len(targets) == 0 {
		return nil, errors.New("goreecloud dns: resolver scheduler requires at least one target")
	}

	seen := make(map[string]struct{}, len(targets))
	copyTargets := make([]ResolverTarget, len(targets))
	for i, target := range targets {
		if target.ID == "" {
			return nil, errors.New("goreecloud dns: resolver target id must not be empty")
		}
		if _, ok := seen[target.ID]; ok {
			return nil, fmt.Errorf("goreecloud dns: duplicate resolver target %q", target.ID)
		}
		seen[target.ID] = struct{}{}
		copyTargets[i] = target
	}
	return copyTargets, nil
}

func (s *ResolverScheduler) orderedTargets(targets []ResolverTarget) []ResolverTarget {
	s.mu.RLock()
	stats := make(map[string]ResolverTargetStats, len(s.stats))
	for id, value := range s.stats {
		stats[id] = value
	}
	s.mu.RUnlock()

	ordered := append([]ResolverTarget(nil), targets...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a := stats[ordered[i].ID]
		b := stats[ordered[j].ID]
		aKnown := a.Successes > 0 && a.LastLatency > 0
		bKnown := b.Successes > 0 && b.LastLatency > 0
		if aKnown != bKnown {
			return aKnown
		}
		if aKnown && bKnown && a.LastLatency != b.LastLatency {
			return a.LastLatency < b.LastLatency
		}
		if a.Failures != b.Failures {
			return a.Failures < b.Failures
		}
		return ordered[i].ID < ordered[j].ID
	})
	return ordered
}

func resolverTargetResponseError(msg *dns.Msg) error {
	if msg == nil {
		return errors.New("resolver target returned nil response")
	}
	switch msg.Rcode {
	case dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeNotImplemented, dns.RcodeFormatError:
		return fmt.Errorf("resolver target returned retryable response code %s", dns.RcodeToString[msg.Rcode])
	default:
		return nil
	}
}

func (s *ResolverScheduler) recordAttempt(id string, latency time.Duration, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stats := s.stats[id]
	if err != nil {
		stats.Failures++
	} else {
		stats.Successes++
		stats.LastLatency = latency
	}
	s.stats[id] = stats
}
