package gcdns_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/gcdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryCachePersistentRoundTrip(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	newCache := func() *gcdns.MemoryCache {
		cache, err := gcdns.NewMemoryCache(gcdns.MemoryCacheConfig{
			Shards:     4,
			ServeStale: true,
			StaleTTL:   5 * time.Minute,
			Now:        func() time.Time { return now },
		})
		require.NoError(t, err)
		return cache
	}

	cache := newCache()
	req := cacheRequest("persistent.example.", "client-a")
	require.NoError(t, cache.Put(context.Background(), req, positiveResult(t, "persistent.example."), 10*time.Minute))

	path := filepath.Join(t.TempDir(), "cache", "state.json")
	require.NoError(t, cache.SavePersistent(path))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	restored := newCache()
	loaded, err := restored.LoadPersistent(path)
	require.NoError(t, err)
	assert.Equal(t, 1, loaded)

	got, ok, err := restored.Get(context.Background(), req)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, got)
	assert.False(t, got.Stale)
	assert.Greater(t, got.CacheTTL, 9*time.Minute)
}

func TestMemoryCachePersistentSkipsExpired(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	cache, err := gcdns.NewMemoryCache(gcdns.MemoryCacheConfig{
		Shards: 2,
		Now:    func() time.Time { return now },
	})
	require.NoError(t, err)

	req := cacheRequest("expired-persistent.example.", "client-a")
	require.NoError(t, cache.Put(context.Background(), req, positiveResult(t, "expired-persistent.example."), time.Minute))
	path := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, cache.SavePersistent(path))

	now = now.Add(2 * time.Minute)
	restored, err := gcdns.NewMemoryCache(gcdns.MemoryCacheConfig{
		Shards: 2,
		Now:    func() time.Time { return now },
	})
	require.NoError(t, err)
	loaded, err := restored.LoadPersistent(path)
	require.NoError(t, err)
	assert.Zero(t, loaded)
	assert.Zero(t, restored.Stats().Entries)
}

func TestMemoryCachePersistentRejectsInvalidState(t *testing.T) {
	cache, err := gcdns.NewMemoryCache(gcdns.MemoryCacheConfig{})
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"version":99,"entries":[]}`), 0o600))
	data := []byte(`{"version":99,"entries":[]}`)
	data = []byte("{\"version\":99,\"entries\":[]}")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	_, err = cache.LoadPersistent(path)
	require.ErrorContains(t, err, "unsupported persistent cache version")
}
