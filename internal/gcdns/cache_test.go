package gcdns_test

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/gcdns"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cacheRequest(name, clientID string) *gcdns.Request {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)

	return &gcdns.Request{
		Message:   m,
		ClientID:  clientID,
		ClientIP:  netip.MustParseAddr("192.0.2.10"),
		Transport: gcdns.TransportDNS,
	}
}

func positiveResult(t *testing.T, name string) *gcdns.Result {
	t.Helper()

	m := new(dns.Msg)
	m.SetReply(cacheRequest(name, "").Message)
	rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN A 192.0.2.20", dns.Fqdn(name)))
	require.NoError(t, err)
	m.Answer = []dns.RR{rr}

	return &gcdns.Result{Message: m, Source: "recursive", CacheTTL: time.Minute}
}

func TestMemoryCachePutGetAndCopyIsolation(t *testing.T) {
	cache, err := gcdns.NewMemoryCache(gcdns.MemoryCacheConfig{Shards: 4})
	require.NoError(t, err)

	req := cacheRequest("Example.ORG.", "client-a")
	want := positiveResult(t, "example.org.")
	require.NoError(t, cache.Put(context.Background(), req, want, time.Minute))

	got, ok, err := cache.Get(context.Background(), cacheRequest("example.org.", "client-a"))
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, got)
	assert.Equal(t, "recursive", got.Source)
	assert.False(t, got.Stale)

	got.Message.Answer = nil
	gotAgain, ok, err := cache.Get(context.Background(), req)
	require.NoError(t, err)
	require.True(t, ok)
	require.Len(t, gotAgain.Message.Answer, 1)

	stats := cache.Stats()
	assert.Equal(t, uint64(2), stats.Hits)
	assert.Equal(t, uint64(1), stats.Puts)
	assert.Equal(t, uint64(1), stats.Entries)
}

func TestMemoryCacheExpires(t *testing.T) {
	now := time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC)
	cache, err := gcdns.NewMemoryCache(gcdns.MemoryCacheConfig{
		Shards: 2,
		Now:    func() time.Time { return now },
	})
	require.NoError(t, err)

	req := cacheRequest("expired.example.", "client-a")
	res := positiveResult(t, "expired.example.")
	require.NoError(t, cache.Put(context.Background(), req, res, time.Minute))
	now = now.Add(time.Minute + time.Nanosecond)

	got, ok, err := cache.Get(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, got)

	stats := cache.Stats()
	assert.Equal(t, uint64(1), stats.Misses)
	assert.Zero(t, stats.Entries)
}

func TestMemoryCacheServeStale(t *testing.T) {
	now := time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC)
	cache, err := gcdns.NewMemoryCache(gcdns.MemoryCacheConfig{
		Shards:     2,
		ServeStale: true,
		StaleTTL:   5 * time.Minute,
		Now:        func() time.Time { return now },
	})
	require.NoError(t, err)

	req := cacheRequest("stale.example.", "client-a")
	res := positiveResult(t, "stale.example.")
	require.NoError(t, cache.Put(context.Background(), req, res, time.Minute))
	now = now.Add(2 * time.Minute)

	got, ok, err := cache.Get(context.Background(), req)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, got)
	assert.True(t, got.Stale)

	stats := cache.Stats()
	assert.Equal(t, uint64(1), stats.Hits)
	assert.Equal(t, uint64(1), stats.StaleHits)

	now = now.Add(5 * time.Minute)
	got, ok, err = cache.Get(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, got)
}

func TestMemoryCacheNegativeEntryAccounting(t *testing.T) {
	cache, err := gcdns.NewMemoryCache(gcdns.MemoryCacheConfig{Shards: 4})
	require.NoError(t, err)

	req := cacheRequest("missing.example.", "client-a")
	m := new(dns.Msg)
	m.SetRcode(req.Message, dns.RcodeNameError)
	res := &gcdns.Result{Message: m, Source: "recursive", CacheTTL: time.Minute}
	require.NoError(t, cache.Put(context.Background(), req, res, time.Minute))

	assert.Equal(t, uint64(1), cache.Stats().NegativeEntries)
	require.NoError(t, cache.Flush(context.Background()))
	assert.Zero(t, cache.Stats().NegativeEntries)
	assert.Zero(t, cache.Stats().Entries)
}

func TestMemoryCachePartitionsClients(t *testing.T) {
	cache, err := gcdns.NewMemoryCache(gcdns.MemoryCacheConfig{Shards: 4})
	require.NoError(t, err)

	reqA := cacheRequest("partition.example.", "client-a")
	reqB := cacheRequest("partition.example.", "client-b")
	res := positiveResult(t, "partition.example.")
	require.NoError(t, cache.Put(context.Background(), reqA, res, time.Minute))

	_, ok, err := cache.Get(context.Background(), reqB)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestMemoryCacheEvictsOldestEntryWithinShard(t *testing.T) {
	now := time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC)
	cache, err := gcdns.NewMemoryCache(gcdns.MemoryCacheConfig{
		Shards:     1,
		MaxEntries: 1,
		Now:        func() time.Time { return now },
	})
	require.NoError(t, err)

	first := cacheRequest("first.example.", "client-a")
	second := cacheRequest("second.example.", "client-a")
	require.NoError(t, cache.Put(context.Background(), first, positiveResult(t, "first.example."), time.Minute))
	now = now.Add(time.Second)
	require.NoError(t, cache.Put(context.Background(), second, positiveResult(t, "second.example."), time.Minute))

	_, ok, err := cache.Get(context.Background(), first)
	require.NoError(t, err)
	assert.False(t, ok)

	_, ok, err = cache.Get(context.Background(), second)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, uint64(1), cache.Stats().Evictions)
	assert.Equal(t, uint64(1), cache.Stats().Entries)
}

func TestMemoryCacheValidation(t *testing.T) {
	_, err := gcdns.NewMemoryCache(gcdns.MemoryCacheConfig{Shards: 3})
	require.ErrorContains(t, err, "power of two")

	_, err = gcdns.NewMemoryCache(gcdns.MemoryCacheConfig{Shards: 4, MaxEntries: 2})
	require.ErrorContains(t, err, "at least the shard count")

	_, err = gcdns.NewMemoryCache(gcdns.MemoryCacheConfig{ServeStale: true})
	require.ErrorContains(t, err, "stale ttl")

	cache, err := gcdns.NewMemoryCache(gcdns.MemoryCacheConfig{})
	require.NoError(t, err)
	err = cache.Put(
		context.Background(),
		cacheRequest("ttl.example.", "client-a"),
		positiveResult(t, "ttl.example."),
		0,
	)
	require.ErrorContains(t, err, "ttl must be positive")
}

func TestMemoryCacheConcurrentAccess(t *testing.T) {
	cache, err := gcdns.NewMemoryCache(gcdns.MemoryCacheConfig{Shards: 16})
	require.NoError(t, err)

	const workers = 32
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()

			name := fmt.Sprintf("worker-%d.example.", i)
			req := cacheRequest(name, fmt.Sprintf("client-%d", i))
			res := &gcdns.Result{Message: new(dns.Msg), Source: "recursive"}
			if putErr := cache.Put(context.Background(), req, res, time.Minute); putErr != nil {
				t.Errorf("put: %v", putErr)
				return
			}
			_, ok, getErr := cache.Get(context.Background(), req)
			if getErr != nil || !ok {
				t.Errorf("get: ok=%v err=%v", ok, getErr)
			}
		}(i)
	}
	wg.Wait()

	stats := cache.Stats()
	assert.Equal(t, uint64(workers), stats.Puts)
	assert.Equal(t, uint64(workers), stats.Hits)
	assert.Equal(t, uint64(workers), stats.Entries)
}
