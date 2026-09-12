package gcdns

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Pipeline coordinates the first-party request path while keeping individual
// DNS subsystems independently testable.
type Pipeline struct {
	Policy    Policy
	Authority Authority
	Cache     Cache
	Resolver  Resolver
	Observer  Observer
}

// Resolve processes req through policy, authoritative, cache, and recursive
// stages in that order. Required subsystem dependencies must not be nil.
func (p *Pipeline) Resolve(ctx context.Context, req *Request) (res *Result, err error) {
	if req == nil || req.Message == nil {
		return nil, errors.New("goreecloud dns: nil request")
	}
	if p.Policy == nil || p.Authority == nil || p.Cache == nil || p.Resolver == nil {
		return nil, errors.New("goreecloud dns: incomplete pipeline")
	}

	if res, handled, err := p.Policy.Evaluate(ctx, req); err != nil || handled {
		p.observe(ctx, "policy", res, false, err, 0)

		return res, err
	}

	if res, handled, err := p.Authority.ResolveAuthoritative(ctx, req); err != nil || handled {
		p.observe(ctx, "authoritative", res, false, err, 0)

		return res, err
	}

	started := time.Now()
	res, ok, err := p.Cache.Get(ctx, req)
	p.observe(ctx, "cache", res, ok, err, time.Since(started))
	if err != nil {
		return nil, fmt.Errorf("goreecloud dns: cache get: %w", err)
	}
	if ok {
		return res, nil
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

	return res, nil
}

func (p *Pipeline) observe(
	ctx context.Context,
	stage string,
	res *Result,
	cacheHit bool,
	err error,
	duration time.Duration,
) {
	if p.Observer == nil {
		return
	}

	e := Event{
		Stage:    stage,
		Duration: duration,
		CacheHit: cacheHit,
		Err:      err,
	}
	if res != nil {
		e.Source = res.Source
		e.Stale = res.Stale
		e.DNSSECStatus = res.DNSSECStatus
	}

	p.Observer.Record(ctx, e)
}
