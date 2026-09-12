package gcdns

import (
	"context"
	"errors"
	"sync"
)

// RequestResolver is implemented by the native Pipeline and other controlled
// request paths that preserve normal policy, authoritative, cache, resolver,
// DNSSEC, and observability behavior.
type RequestResolver interface {
	Resolve(ctx context.Context, req *Request) (*Result, error)
}

// PrefetchRunner executes Beacon Cache refresh candidates through a complete
// request resolver. It never calls a network resolver directly.
type PrefetchRunner struct {
	resolver    RequestResolver
	maxParallel int
}

// NewPrefetchRunner creates a bounded proactive-refresh executor.
func NewPrefetchRunner(resolver RequestResolver, maxParallel int) (*PrefetchRunner, error) {
	if resolver == nil {
		return nil, errors.New("goreecloud dns: prefetch runner requires a request resolver")
	}
	if maxParallel <= 0 {
		return nil, errors.New("goreecloud dns: prefetch runner max parallel must be positive")
	}
	return &PrefetchRunner{resolver: resolver, maxParallel: maxParallel}, nil
}

// Refresh executes candidates with bounded concurrency. Each candidate is
// defensively copied and sent through the supplied complete request path.
// Individual refresh failures are returned for observability and retry policy;
// they do not abort unrelated candidates.
func (r *PrefetchRunner) Refresh(ctx context.Context, candidates []PrefetchCandidate) []error {
	if len(candidates) == 0 {
		return nil
	}

	sem := make(chan struct{}, r.maxParallel)
	errs := make([]error, len(candidates))
	var wg sync.WaitGroup

	for i, candidate := range candidates {
		i := i
		candidate := candidate
		wg.Add(1)
		go func() {
			defer wg.Done()
			if candidate.Request == nil || candidate.Request.Message == nil {
				errs[i] = errors.New("goreecloud dns: prefetch candidate has nil request")
				return
			}

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				errs[i] = ctx.Err()
				return
			}

			_, errs[i] = r.resolver.Resolve(ctx, cloneRequest(candidate.Request))
		}()
	}

	wg.Wait()
	return errs
}
