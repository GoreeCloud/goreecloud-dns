package gcdns

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMemoryCachePartitionsSameClientAcrossAddresses(t *testing.T) {
	clock := &cacheClock{now: time.Unix(1_700_000_000, 0)}
	cache := newTestMemoryCache(t, clock, 16, false)
	reqA := cacheRequest("service.internal.", "device-a")
	reqA.ClientIP = netip.MustParseAddr("10.10.1.20")
	reqB := cacheRequest("service.internal.", "device-a")
	reqB.ClientIP = netip.MustParseAddr("10.20.1.20")

	require.NoError(t, cache.Put(context.Background(), reqA, cacheAnswer("service.internal.", 60), time.Minute))
	_, ok, err := cache.Get(context.Background(), reqB)
	require.NoError(t, err)
	require.False(t, ok)
}
