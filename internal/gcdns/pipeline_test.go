package gcdns

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type policyFunc func(context.Context, *Request) (*Result, bool, error)

func (f policyFunc) Evaluate(ctx context.Context, req *Request) (*Result, bool, error) {
	return f(ctx, req)
}

type authorityFunc func(context.Context, *Request) (*Result, bool, error)

func (f authorityFunc) ResolveAuthoritative(ctx context.Context, req *Request) (*Result, bool, error) {
	return f(ctx, req)
}

type resolverFunc func(context.Context, *Request) (*Result, error)

func (f resolverFunc) Resolve(ctx context.Context, req *Request) (*Result, error) { return f(ctx, req) }

type cacheStub struct {
	result *Result
	ok     bool
	puts   int
	ttl    time.Duration
}

func (c *cacheStub) Get(context.Context, *Request) (*Result, bool, error) { return c.result, c.ok, nil }

func (c *cacheStub) Put(_ context.Context, _ *Request, _ *Result, ttl time.Duration) error {
	c.puts++
	c.ttl = ttl
	return nil
}
func (c *cacheStub) Flush(context.Context) error { return nil }

func testRequest() *Request {
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	return &Request{Message: m, Transport: TransportDNS}
}

func passPolicy() Policy {
	return policyFunc(func(context.Context, *Request) (*Result, bool, error) { return nil, false, nil })
}

func passAuthority() Authority {
	return authorityFunc(func(context.Context, *Request) (*Result, bool, error) { return nil, false, nil })
}

func TestPipelineCacheHitSkipsResolver(t *testing.T) {
	cached := &Result{Message: new(dns.Msg), Source: "cache"}
	cache := &cacheStub{result: cached, ok: true}
	calls := 0
	p := &Pipeline{
		Policy: passPolicy(), Authority: passAuthority(), Cache: cache,
		Resolver: resolverFunc(func(context.Context, *Request) (*Result, error) { calls++; return nil, nil }),
	}

	got, err := p.Resolve(context.Background(), testRequest())
	require.NoError(t, err)
	require.Same(t, cached, got)
	require.Zero(t, calls)
}

func TestPipelineStoresCacheableResolverResult(t *testing.T) {
	cache := &cacheStub{}
	want := &Result{Message: new(dns.Msg), Source: "resolver", CacheTTL: 5 * time.Minute, DNSSECStatus: DNSSECSecure}
	p := &Pipeline{
		Policy: passPolicy(), Authority: passAuthority(), Cache: cache,
		Resolver: resolverFunc(func(context.Context, *Request) (*Result, error) { return want, nil }),
	}

	got, err := p.Resolve(context.Background(), testRequest())
	require.NoError(t, err)
	require.Same(t, want, got)
	require.Equal(t, 1, cache.puts)
	require.Equal(t, want.CacheTTL, cache.ttl)
}

func TestPipelineRejectsBogusDNSSECBeforeCache(t *testing.T) {
	cache := &cacheStub{}
	p := &Pipeline{
		Policy: passPolicy(), Authority: passAuthority(), Cache: cache,
		Resolver: resolverFunc(func(context.Context, *Request) (*Result, error) {
			return &Result{Message: new(dns.Msg), Source: "resolver", CacheTTL: time.Minute, DNSSECStatus: DNSSECBogus}, nil
		}),
	}

	_, err := p.Resolve(context.Background(), testRequest())
	require.ErrorContains(t, err, "bogus dnssec")
	require.Zero(t, cache.puts)
}

func TestPipelinePolicyShortCircuits(t *testing.T) {
	want := &Result{Message: new(dns.Msg), Source: "policy"}
	calls := 0
	p := &Pipeline{
		Policy:    policyFunc(func(context.Context, *Request) (*Result, bool, error) { return want, true, nil }),
		Authority: passAuthority(), Cache: &cacheStub{},
		Resolver: resolverFunc(func(context.Context, *Request) (*Result, error) { calls++; return nil, nil }),
	}
	got, err := p.Resolve(context.Background(), testRequest())
	require.NoError(t, err)
	require.Same(t, want, got)
	require.Zero(t, calls)
}
