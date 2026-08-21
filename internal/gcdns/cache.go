package gcdns

import (
	"context"
	"errors"
	"hash/fnv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const defaultCacheShards = 16

// MemoryCacheConfig configures the first-party in-memory DNS cache.
type MemoryCacheConfig struct {
	// Shards controls lock partitioning. It must be a power of two.
	Shards uint

	// MaxEntries limits the total number of entries. Zero means unlimited.
	MaxEntries int

	// ServeStale allows expired entries to remain usable for StaleTTL.
	ServeStale bool
	StaleTTL   time.Duration

	// Now exists so cache expiration can be tested deterministically. If nil,
	// time.Now is used.
	Now func() time.Time
}

// CacheStats is a concurrency-safe snapshot of native cache behavior.
type CacheStats struct {
	Hits            uint64
	Misses          uint64
	StaleHits       uint64
	Puts            uint64
	Evictions       uint64
	Entries         uint64
	NegativeEntries uint64
}

type cacheCounters struct {
	hits       atomic.Uint64
	misses     atomic.Uint64
	staleHits  atomic.Uint64
	puts       atomic.Uint64
	evictions  atomic.Uint64
	entries    atomic.Uint64
	negative   atomic.Uint64
}

type memoryCacheEntry struct {
	result    *Result
	expiresAt time.Time
	staleAt   time.Time
	createdAt time.Time
	negative  bool
}

type memoryCacheShard struct {
	mu      sync.RWMutex
	entries map[string]*memoryCacheEntry
	limit   int
}

// MemoryCache is a sharded, concurrency-safe first-party DNS cache.
type MemoryCache struct {
	shards     []memoryCacheShard
	shardMask  uint64
	serveStale bool
	staleTTL   time.Duration
	now        func() time.Time
	stats      cacheCounters
}

// NewMemoryCache returns a native in-memory cache with safe validation.
func NewMemoryCache(conf MemoryCacheConfig) (*MemoryCache, error) {
	shards := conf.Shards
	if shards == 0 {
		shards = defaultCacheShards
	}
	if shards&(shards-1) != 0 {
		return nil, errors.New("goreecloud dns: cache shard count must be a power of two")
	}
	if conf.MaxEntries < 0 {
		return nil, errors.New("goreecloud dns: cache max entries must not be negative")
	}
	if conf.StaleTTL < 0 {
		return nil, errors.New("goreecloud dns: cache stale ttl must not be negative")
	}
	if conf.ServeStale && conf.StaleTTL == 0 {
		return nil, errors.New("goreecloud dns: cache stale ttl must be positive when serve-stale is enabled")
	}

	now := conf.Now
	if now == nil {
		now = time.Now
	}

	c := &MemoryCache{
		shards:     make([]memoryCacheShard, shards),
		shardMask:  uint64(shards - 1),
		serveStale: conf.ServeStale,
		staleTTL:   conf.StaleTTL,
		now:        now,
	}

	baseLimit := 0
	extra := 0
	if conf.MaxEntries > 0 {
		baseLimit = conf.MaxEntries / int(shards)
		extra = conf.MaxEntries % int(shards)
	}
	for i := range c.shards {
		limit := baseLimit
		if i < extra {
			limit++
		}
		c.shards[i] = memoryCacheShard{
			entries: make(map[string]*memoryCacheEntry),
			limit:   limit,
		}
	}

	return c, nil
}

// Get implements Cache. Returned DNS messages are copies so callers cannot
// mutate cached state. Expired entries are removed unless serve-stale permits
// a bounded stale response.
func (c *MemoryCache) Get(_ context.Context, req *Request) (*Result, bool, error) {
	key, err := cacheKey(req)
	if err != nil {
		return nil, false, err
	}

	shard := c.shard(key)
	now := c.now()

	shard.mu.RLock()
	entry, ok := shard.entries[key]
	if ok && now.Before(entry.expiresAt) {
		res := cloneResult(entry.result)
		shard.mu.RUnlock()
		c.stats.hits.Add(1)

		return res, true, nil
	}
	if ok && c.serveStale && now.Before(entry.staleAt) {
		res := cloneResult(entry.result)
		res.Stale = true
		shard.mu.RUnlock()
		c.stats.hits.Add(1)
		c.stats.staleHits.Add(1)

		return res, true, nil
	}
	shard.mu.RUnlock()

	if ok {
		shard.mu.Lock()
		if current, exists := shard.entries[key]; exists && !c.usable(current, now) {
			delete(shard.entries, key)
			c.decrementEntryStats(current)
		}
		shard.mu.Unlock()
	}

	c.stats.misses.Add(1)

	return nil, false, nil
}

// Put implements Cache. Non-positive TTLs are rejected so callers cannot
// accidentally create immortal or immediately invalid entries.
func (c *MemoryCache) Put(_ context.Context, req *Request, res *Result, ttl time.Duration) error {
	if ttl <= 0 {
		return errors.New("goreecloud dns: cache ttl must be positive")
	}
	if res == nil || res.Message == nil {
		return errors.New("goreecloud dns: cache result must contain a dns message")
	}

	key, err := cacheKey(req)
	if err != nil {
		return err
	}

	now := c.now()
	entry := &memoryCacheEntry{
		result:    cloneResult(res),
		expiresAt: now.Add(ttl),
		createdAt: now,
		negative:  isNegativeResponse(res.Message),
	}
	entry.result.Stale = false
	entry.staleAt = entry.expiresAt
	if c.serveStale {
		entry.staleAt = entry.expiresAt.Add(c.staleTTL)
	}

	shard := c.shard(key)
	shard.mu.Lock()
	if old, exists := shard.entries[key]; exists {
		c.decrementEntryStats(old)
	}
	shard.entries[key] = entry
	c.incrementEntryStats(entry)
	c.enforceLimit(shard, key)
	shard.mu.Unlock()

	c.stats.puts.Add(1)

	return nil
}

// Flush implements Cache and atomically clears each shard.
func (c *MemoryCache) Flush(_ context.Context) error {
	for i := range c.shards {
		shard := &c.shards[i]
		shard.mu.Lock()
		shard.entries = make(map[string]*memoryCacheEntry)
		shard.mu.Unlock()
	}
	c.stats.entries.Store(0)
	c.stats.negative.Store(0)

	return nil
}

// Stats returns a point-in-time cache statistics snapshot.
func (c *MemoryCache) Stats() CacheStats {
	return CacheStats{
		Hits:            c.stats.hits.Load(),
		Misses:          c.stats.misses.Load(),
		StaleHits:       c.stats.staleHits.Load(),
		Puts:            c.stats.puts.Load(),
		Evictions:       c.stats.evictions.Load(),
		Entries:         c.stats.entries.Load(),
		NegativeEntries: c.stats.negative.Load(),
	}
}

func (c *MemoryCache) usable(entry *memoryCacheEntry, now time.Time) bool {
	if now.Before(entry.expiresAt) {
		return true
	}

	return c.serveStale && now.Before(entry.staleAt)
}

func (c *MemoryCache) shard(key string) *memoryCacheShard {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))

	return &c.shards[h.Sum64()&c.shardMask]
}

func (c *MemoryCache) enforceLimit(shard *memoryCacheShard, insertedKey string) {
	if shard.limit == 0 || len(shard.entries) <= shard.limit {
		return
	}

	var oldestKey string
	var oldest *memoryCacheEntry
	for key, entry := range shard.entries {
		if key == insertedKey && len(shard.entries) > 1 {
			continue
		}
		if oldest == nil || entry.createdAt.Before(oldest.createdAt) {
			oldestKey = key
			oldest = entry
		}
	}
	if oldest == nil {
		return
	}

	delete(shard.entries, oldestKey)
	c.decrementEntryStats(oldest)
	c.stats.evictions.Add(1)
}

func (c *MemoryCache) incrementEntryStats(entry *memoryCacheEntry) {
	c.stats.entries.Add(1)
	if entry.negative {
		c.stats.negative.Add(1)
	}
}

func (c *MemoryCache) decrementEntryStats(entry *memoryCacheEntry) {
	c.stats.entries.Add(^uint64(0))
	if entry.negative {
		c.stats.negative.Add(^uint64(0))
	}
}

func cacheKey(req *Request) (string, error) {
	if req == nil || req.Message == nil || len(req.Message.Question) != 1 {
		return "", errors.New("goreecloud dns: cache requires exactly one dns question")
	}

	q := req.Message.Question[0]
	clientPartition := req.ClientID
	if clientPartition == "" && req.ClientIP.IsValid() {
		clientPartition = req.ClientIP.String()
	}

	return strings.ToLower(dns.Fqdn(q.Name)) + "|" +
		dns.TypeToString[q.Qtype] + "|" + dns.ClassToString[q.Qclass] + "|" + clientPartition, nil
}

func cloneResult(res *Result) *Result {
	if res == nil {
		return nil
	}

	clone := *res
	if res.Message != nil {
		clone.Message = res.Message.Copy()
	}

	return &clone
}

func isNegativeResponse(msg *dns.Msg) bool {
	if msg == nil {
		return false
	}
	if msg.Rcode == dns.RcodeNameError {
		return true
	}

	return msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0
}
