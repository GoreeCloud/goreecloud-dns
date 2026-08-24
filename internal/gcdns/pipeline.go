package gcdns

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Pipeline coordinates the first-party DNS request path while keeping each
// subsystem independently replaceable and testable.
type Pipeline struct {
	Policy    Policy
	Authority Authority
	Cache     Cache
	Resolver  Resolver
	Observer  Observer
}

// Resolve executes policy -> authority -> cache -> resolver. Bogus DNSSEC
// results are rejected before cache insertion. RFC 9824 Compact Denial results
// are cached in normalized semantic form and presented to each downstream
// client according to that request's DO/CO capability only after cache work.
func (p *Pipeline) Resolve(ctx context.Context, req *Request) (*Result, error) {
	if req == nil || req.Message == nil {
		return nil, errors.New("goreecloud dns: nil request")
	}
	if p.Policy == nil || p.Authority == nil || p.Cache == nil || p.Resolver == nil {
		return nil, errors.New("goreecloud dns: incomplete native pipeline")
	}

	if res, handled, err := p.Policy.Evaluate(ctx, req); err != nil || handled {
		p.observe(ctx, "policy", res, false, err, 0)
		return prepareCompactDenialForClient(req, res), err
	}

	if res, handled, err := p.Authority.ResolveAuthoritative(ctx, req); err != nil || handled {
		p.observe(ctx, "authoritative", res, false, err, 0)
		return prepareCompactDenialForClient(req, res), err
	}

	started := time.Now()
	res, ok, err := p.Cache.Get(ctx, req)
	p.observe(ctx, "cache", res, ok, err, time.Since(started))
	if err != nil {
		return nil, fmt.Errorf("goreecloud dns: cache get: %w", err)
	}
	if ok {
		return prepareCompactDenialForClient(req, res), nil
	}

	started = time.Now()
	res, err = p.Resolver.Resolve(ctx, req)
	p.observe(ctx, "resolver", res, false, err, time.Since(started))
	if err != nil {
		return nil, fmt.Errorf("goreecloud dns: resolve: %w", err)
	}
	if res == nil || res.Message == nil {
		return nil, errors.New("goreecloud dns: resolver returned nil response")
	}
	if res.DNSSECStatus == DNSSECBogus {
		return nil, errors.New("goreecloud dns: refusing bogus dnssec result")
	}

	if res.CacheTTL > 0 {
		started = time.Now()
		err = p.Cache.Put(ctx, req, res, res.CacheTTL)
		p.observe(ctx, "cache-store", res, false, err, time.Since(started))
		if err != nil {
			return nil, fmt.Errorf("goreecloud dns: cache put: %w", err)
		}
	}

	return prepareCompactDenialForClient(req, res), nil
}

func (p *Pipeline) observe(ctx context.Context, stage string, res *Result, cacheHit bool, err error, duration time.Duration) {
	if p.Observer == nil {
		return
	}

	e := Event{Stage: stage, Duration: duration, CacheHit: cacheHit, Err: err}
	if res != nil {
		e.Source = res.Source
		e.Stale = res.Stale
		e.DNSSECStatus = res.DNSSECStatus
	}
	p.Observer.Record(ctx, e)
}
