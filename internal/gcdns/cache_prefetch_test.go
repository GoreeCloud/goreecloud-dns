package gcdns_test

import (
	"context"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/gcdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrefetchCacheSelectsPopularExpiringEntry(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	memory, err := gcdns.NewMemoryCache(gcdns.MemoryCacheConfig{
		Shards: 4,
		Now:    func() time.Time { return now },
	})
	require.NoError(t, err)

	cache, err := gcdns.NewPrefetchCache(memory, gcdns.PrefetchConfig{
		MinimumHits:  2,
		RefreshWithin: 30 * time.Second,
	})
	require.NoError(t, err)

	req := cacheRequest("prefetch.example.", "client-a")
	require.NoError(t, cache.Put(context.Background(), req, positiveResult(t, "prefetch.example."), time.Minute))

	for range 2 {
		_, ok, getErr := cache.Get(context.Background(), req)
		require.NoError(t, getErr)
		require.True(t, ok)
	}

	now = now.Add(40 * time.Second)
	candidates, err := cache.Candidates(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	assert.Equal(t, uint64(2), candidates[0].Hits)
	assert.LessOrEqual(t, candidates[0].RemainingTTL, 20*time.Second)
	assert.Equal(t, "prefetch.example.", candidates[0].Request.Message.Question[0].Name)
}

func TestPrefetchCacheDoesNotSelectColdOrFreshEntry(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	memory, err := gcdns.NewMemoryCache(gcdns.MemoryCacheConfig{
		Shards: 4,
		Now:    func() time.Time { return now },
	})
	require.NoError(t, err)
	cache, err := gcdns.NewPrefetchCache(memory, gcdns.PrefetchConfig{
		MinimumHits:  2,
		RefreshWithin: 15 * time.Second,
	})
	require.NoError(t, err)

	req := cacheRequest("cold.example.", "client-a")
	require.NoError(t, cache.Put(context.Background(), req, positiveResult(t, "cold.example."), time.Minute))
	_, ok, err := cache.Get(context.Background(), req)
	require.NoError(t, err)
	require.True(t, ok)

	candidates, err := cache.Candidates(context.Background(), 10)
	require.NoError(t, err)
	assert.Empty(t, candidates)
}

func TestPrefetchCacheFlushClearsPopularity(t *testing.T) {
	memory, err := gcdns.NewMemoryCache(gcdns.MemoryCacheConfig{Shards: 4})
	require.NoError(t, err)
	cache, err := gcdns.NewPrefetchCache(memory, gcdns.PrefetchConfig{
		MinimumHits:  1,
		RefreshWithin: time.Minute,
	})
	require.NoError(t, err)

	req := cacheRequest("flush-prefetch.example.", "client-a")
	require.NoError(t, cache.Put(context.Background(), req, positiveResult(t, "flush-prefetch.example."), time.Minute))
	_, ok, err := cache.Get(context.Background(), req)
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, cache.Flush(context.Background()))

	candidates, err := cache.Candidates(context.Background(), 10)
	require.NoError(t, err)
	assert.Empty(t, candidates)
}

func TestPrefetchCacheValidation(t *testing.T) {
	memory, err := gcdns.NewMemoryCache(gcdns.MemoryCacheConfig{})
	require.NoError(t, err)

	_, err = gcdns.NewPrefetchCache(memory, gcdns.PrefetchConfig{})
	require.ErrorContains(t, err, "minimum hits")

	_, err = gcdns.NewPrefetchCache(memory, gcdns.PrefetchConfig{MinimumHits: 1})
	require.ErrorContains(t, err, "refresh window")
}
