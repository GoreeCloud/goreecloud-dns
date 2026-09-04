package gcdns

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type cacheClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *cacheClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *cacheClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func cacheRequest(name, client string) *Request {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	return &Request{Message: m, ClientID: client, ClientIP: netip.MustParseAddr("192.0.2.10"), Transport: TransportDNS}
}

func cacheAnswer(name string, ttl uint32) *Result {
	m := new(dns.Msg)
	m.SetReply(cacheRequest(name, "client-a").Message)
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: []byte{192, 0, 2, 55}}}
	return &Result{Message: m, Source: "resolver", CacheTTL: time.Duration(ttl) * time.Second, DNSSECStatus: DNSSECSecure}
}

func newTestMemoryCache(t *testing.T, clock *cacheClock, max int, stale bool) *MemoryCache {
	t.Helper()
	c, err := NewMemoryCache(MemoryCacheConfig{Shards: 4, MaxEntries: max, ServeStale: stale, StaleTTL: 30 * time.Second, Now: clock.Now})
	require.NoError(t, err)
	return c
}

func TestMemoryCachePutGetAndCopyIsolation(t *testing.T) {
	clock := &cacheClock{now: time.Unix(1_700_000_000, 0)}
	cache := newTestMemoryCache(t, clock, 16, false)
	req := cacheRequest("example.org.", "client-a")
	want := cacheAnswer("example.org.", 120)

	require.NoError(t, cache.Put(context.Background(), req, want, 2*time.Minute))
	got, ok, err := cache.Get(context.Background(), req)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, uint32(120), got.Message.Answer[0].Header().Ttl)

	got.Message.Answer[0].Header().Ttl = 1
	again, ok, err := cache.Get(context.Background(), req)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, uint32(120), again.Message.Answer[0].Header().Ttl)
}

func TestMemoryCacheAgesWireTTL(t *testing.T) {
	clock := &cacheClock{now: time.Unix(1_700_000_000, 0)}
	cache := newTestMemoryCache(t, clock, 16, false)
	req := cacheRequest("example.org.", "client-a")
	require.NoError(t, cache.Put(context.Background(), req, cacheAnswer("example.org.", 120), 2*time.Minute))
	clock.Advance(35 * time.Second)

	got, ok, err := cache.Get(context.Background(), req)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, uint32(85), got.Message.Answer[0].Header().Ttl)
}

func TestMemoryCacheExpires(t *testing.T) {
	clock := &cacheClock{now: time.Unix(1_700_000_000, 0)}
	cache := newTestMemoryCache(t, clock, 16, false)
	req := cacheRequest("example.org.", "client-a")
	require.NoError(t, cache.Put(context.Background(), req, cacheAnswer("example.org.", 10), 10*time.Second))
	clock.Advance(11 * time.Second)

	got, ok, err := cache.Get(context.Background(), req)
	require.NoError(t, err)
	require.False(t, ok)
	require.Nil(t, got)
	require.Equal(t, uint64(1), cache.Stats().Misses)
}

func TestMemoryCacheServeStale(t *testing.T) {
	clock := &cacheClock{now: time.Unix(1_700_000_000, 0)}
	cache := newTestMemoryCache(t, clock, 16, true)
	req := cacheRequest("example.org.", "client-a")
	require.NoError(t, cache.Put(context.Background(), req, cacheAnswer("example.org.", 10), 10*time.Second))
	clock.Advance(20 * time.Second)

	got, ok, err := cache.Get(context.Background(), req)
	require.NoError(t, err)
	require.True(t, ok)
	require.True(t, got.Stale)
	require.Equal(t, uint32(0), got.Message.Answer[0].Header().Ttl)
	require.Equal(t, uint64(1), cache.Stats().StaleHits)

	clock.Advance(21 * time.Second)
	_, ok, err = cache.Get(context.Background(), req)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestMemoryCacheNegativeEntryAccounting(t *testing.T) {
	clock := &cacheClock{now: time.Unix(1_700_000_000, 0)}
	cache := newTestMemoryCache(t, clock, 16, false)
	req := cacheRequest("missing.example.", "client-a")
	m := new(dns.Msg)
	m.SetRcode(req.Message, dns.RcodeNameError)
	res := &Result{Message: m, Source: "resolver", DNSSECStatus: DNSSECSecure}

	require.NoError(t, cache.Put(context.Background(), req, res, time.Minute))
	require.Equal(t, uint64(1), cache.Stats().NegativeEntries)
	require.NoError(t, cache.Flush(context.Background()))
	require.Zero(t, cache.Stats().NegativeEntries)
}

func TestMemoryCachePartitionsClients(t *testing.T) {
	clock := &cacheClock{now: time.Unix(1_700_000_000, 0)}
	cache := newTestMemoryCache(t, clock, 16, false)
	reqA := cacheRequest("example.org.", "client-a")
	reqB := cacheRequest("example.org.", "client-b")
	require.NoError(t, cache.Put(context.Background(), reqA, cacheAnswer("example.org.", 60), time.Minute))

	_, ok, err := cache.Get(context.Background(), reqB)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestMemoryCacheEvictsWithinBound(t *testing.T) {
	clock := &cacheClock{now: time.Unix(1_700_000_000, 0)}
	cache, err := NewMemoryCache(MemoryCacheConfig{Shards: 1, MaxEntries: 2, Now: clock.Now})
	require.NoError(t, err)
	for _, name := range []string{"one.example.", "two.example.", "three.example."} {
		req := cacheRequest(name, "client-a")
		require.NoError(t, cache.Put(context.Background(), req, cacheAnswer(name, 60), time.Minute))
	}
	require.Equal(t, uint64(2), cache.Stats().Entries)
	require.Equal(t, uint64(1), cache.Stats().Evictions)
}

func TestMemoryCacheConcurrentAccess(t *testing.T) {
	clock := &cacheClock{now: time.Unix(1_700_000_000, 0)}
	cache := newTestMemoryCache(t, clock, 128, false)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				req := cacheRequest("concurrent.example.", "client-a")
				_ = cache.Put(ctx, req, cacheAnswer("concurrent.example.", 60), time.Minute)
				_, _, _ = cache.Get(ctx, req)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, uint64(1), cache.Stats().Entries)
}

func TestMemoryCacheValidation(t *testing.T) {
	_, err := NewMemoryCache(MemoryCacheConfig{Shards: 3, MaxEntries: 10})
	require.ErrorContains(t, err, "power of two")
	_, err = NewMemoryCache(MemoryCacheConfig{Shards: 4, MaxEntries: 0})
	require.ErrorContains(t, err, "max entries")
	_, err = NewMemoryCache(MemoryCacheConfig{Shards: 4, MaxEntries: 10, ServeStale: true})
	require.ErrorContains(t, err, "stale ttl")
}
