package gcdns_test

import (
	"context"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/gcdns"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type policyFunc func(context.Context, *gcdns.Request) (*gcdns.Result, bool, error)

func (f policyFunc) Evaluate(ctx context.Context, req *gcdns.Request) (*gcdns.Result, bool, error) {
	return f(ctx, req)
}

type authorityFunc func(context.Context, *gcdns.Request) (*gcdns.Result, bool, error)

func (f authorityFunc) ResolveAuthoritative(ctx context.Context, req *gcdns.Request) (*gcdns.Result, bool, error) {
	return f(ctx, req)
}

type resolverFunc func(context.Context, *gcdns.Request) (*gcdns.Result, error)

func (f resolverFunc) Resolve(ctx context.Context, req *gcdns.Request) (*gcdns.Result, error) {
	return f(ctx, req)
}

type cacheStub struct {
	getResult *gcdns.Result
	getOK     bool
	putTTL    time.Duration
	putCalls  int
}

func (c *cacheStub) Get(context.Context, *gcdns.Request) (*gcdns.Result, bool, error) {
	return c.getResult, c.getOK, nil
}

func (c *cacheStub) Put(_ context.Context, _ *gcdns.Request, _ *gcdns.Result, ttl time.Duration) error {
	c.putCalls++
	c.putTTL = ttl

	return nil
}

func (c *cacheStub) Flush(context.Context) error { return nil }

func newRequest() *gcdns.Request {
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)

	return &gcdns.Request{Message: m, Transport: gcdns.TransportDNS}
}

func passPolicy() gcdns.Policy {
	return policyFunc(func(context.Context, *gcdns.Request) (*gcdns.Result, bool, error) {
		return nil, false, nil
	})
}

func passAuthority() gcdns.Authority {
	return authorityFunc(func(context.Context, *gcdns.Request) (*gcdns.Result, bool, error) {
		return nil, false, nil
	})
}

func TestPipelinePolicyShortCircuit(t *testing.T) {
	want := &gcdns.Result{Message: new(dns.Msg), Source: "policy"}
	cache := &cacheStub{}
	resolverCalls := 0
	p := &gcdns.Pipeline{
		Policy: policyFunc(func(context.Context, *gcdns.Request) (*gcdns.Result, bool, error) {
			return want, true, nil
		}),
		Authority: passAuthority(),
		Cache:     cache,
		Resolver: resolverFunc(func(context.Context, *gcdns.Request) (*gcdns.Result, error) {
			resolverCalls++
			return nil, nil
		}),
	}

	got, err := p.Resolve(context.Background(), newRequest())
	require.NoError(t, err)
	assert.Same(t, want, got)
	assert.Zero(t, resolverCalls)
	assert.Zero(t, cache.putCalls)
}

func TestPipelineAuthoritativeShortCircuit(t *testing.T) {
	want := &gcdns.Result{Message: new(dns.Msg), Source: "authoritative"}
	cache := &cacheStub{}
	resolverCalls := 0
	p := &gcdns.Pipeline{
		Policy: passPolicy(),
		Authority: authorityFunc(func(context.Context, *gcdns.Request) (*gcdns.Result, bool, error) {
			return want, true, nil
		}),
		Cache: cache,
		Resolver: resolverFunc(func(context.Context, *gcdns.Request) (*gcdns.Result, error) {
			resolverCalls++
			return nil, nil
		}),
	}

	got, err := p.Resolve(context.Background(), newRequest())
	require.NoError(t, err)
	assert.Same(t, want, got)
	assert.Zero(t, resolverCalls)
	assert.Zero(t, cache.putCalls)
}

func TestPipelineCacheHit(t *testing.T) {
	want := &gcdns.Result{Message: new(dns.Msg), Source: "cache"}
	cache := &cacheStub{getResult: want, getOK: true}
	resolverCalls := 0
	p := &gcdns.Pipeline{
		Policy:    passPolicy(),
		Authority: passAuthority(),
		Cache:     cache,
		Resolver: resolverFunc(func(context.Context, *gcdns.Request) (*gcdns.Result, error) {
			resolverCalls++
			return nil, nil
		}),
	}

	got, err := p.Resolve(context.Background(), newRequest())
	require.NoError(t, err)
	assert.Same(t, want, got)
	assert.Zero(t, resolverCalls)
}

func TestPipelineResolverStoresCacheableResult(t *testing.T) {
	const ttl = 5 * time.Minute
	want := &gcdns.Result{Message: new(dns.Msg), Source: "recursive", CacheTTL: ttl}
	cache := &cacheStub{}
	p := &gcdns.Pipeline{
		Policy:    passPolicy(),
		Authority: passAuthority(),
		Cache:     cache,
		Resolver: resolverFunc(func(context.Context, *gcdns.Request) (*gcdns.Result, error) {
			return want, nil
		}),
	}

	got, err := p.Resolve(context.Background(), newRequest())
	require.NoError(t, err)
	assert.Same(t, want, got)
	assert.Equal(t, 1, cache.putCalls)
	assert.Equal(t, ttl, cache.putTTL)
}

func TestPipelineResolverSkipsNonCacheableResult(t *testing.T) {
	cache := &cacheStub{}
	p := &gcdns.Pipeline{
		Policy:    passPolicy(),
		Authority: passAuthority(),
		Cache:     cache,
		Resolver: resolverFunc(func(context.Context, *gcdns.Request) (*gcdns.Result, error) {
			return &gcdns.Result{Message: new(dns.Msg), Source: "recursive"}, nil
		}),
	}

	_, err := p.Resolve(context.Background(), newRequest())
	require.NoError(t, err)
	assert.Zero(t, cache.putCalls)
}
