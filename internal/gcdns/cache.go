package gcdns

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// MemoryCacheConfig controls the first-party Beacon in-memory DNS cache.
type MemoryCacheConfig struct {
	Shards     int
	MaxEntries int
	ServeStale bool
	StaleTTL   time.Duration
	Now        func() time.Time
}

// CacheStats is a point-in-time snapshot of cache activity.
type CacheStats struct {
	Hits            uint64
	Misses          uint64
	StaleHits       uint64
	Puts            uint64
	Evictions       uint64
	NegativeEntries uint64
	Entries         uint64
}

type memoryCacheEntry struct {
	result    *Result
	storedAt  time.Time
	expiresAt time.Time
	staleTo   time.Time
	negative  bool
	sequence  uint64
}

type memoryCacheShard struct {
	mu      sync.RWMutex
	entries map[string]*memoryCacheEntry
	limit   int
}

// MemoryCache is a bounded, sharded, concurrency-safe first-party DNS cache.
// The whole-cache gate makes Flush mutually exclusive with Get and Put while
// shard locks keep ordinary query traffic independent across partitions.
type MemoryCache struct {
	gate     sync.RWMutex
	shards   []memoryCacheShard
	mask     uint64
	now      func() time.Time
	stale    bool
	staleTTL time.Duration
	seq      atomic.Uint64

	hits      atomic.Uint64
	misses    atomic.Uint64
	staleHits atomic.Uint64
	puts      atomic.Uint64
	evictions atomic.Uint64
	negative  atomic.Uint64
}

// NewMemoryCache creates a cache with a power-of-two shard count.
func NewMemoryCache(cfg MemoryCacheConfig) (*MemoryCache, error) {
	if cfg.Shards <= 0 || cfg.Shards&(cfg.Shards-1) != 0 {
		return nil, errors.New("goreecloud dns: cache shard count must be a positive power of two")
	}
	if cfg.MaxEntries <= 0 {
		return nil, errors.New("goreecloud dns: cache max entries must be positive")
	}
	if cfg.ServeStale && cfg.StaleTTL <= 0 {
		return nil, errors.New("goreecloud dns: stale ttl must be positive when serve-stale is enabled")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	perShard := (cfg.MaxEntries + cfg.Shards - 1) / cfg.Shards
	c := &MemoryCache{
		shards:   make([]memoryCacheShard, cfg.Shards),
		mask:     uint64(cfg.Shards - 1),
		now:      cfg.Now,
		stale:    cfg.ServeStale,
		staleTTL: cfg.StaleTTL,
	}
	for i := range c.shards {
		c.shards[i] = memoryCacheShard{entries: make(map[string]*memoryCacheEntry), limit: perShard}
	}
	return c, nil
}

// Get returns a defensive copy of a fresh or permitted stale cache entry.
func (c *MemoryCache) Get(ctx context.Context, req *Request) (*Result, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	key, hash, err := cacheKey(req)
	if err != nil {
		return nil, false, err
	}

	c.gate.RLock()
	defer c.gate.RUnlock()

	s := &c.shards[hash&c.mask]
	s.mu.RLock()
	entry := s.entries[key]
	if entry == nil {
		s.mu.RUnlock()
		c.misses.Add(1)
		return nil, false, nil
	}
	now := c.now()
	fresh := now.Before(entry.expiresAt)
	stale := !fresh && c.stale && now.Before(entry.staleTo)
	if !fresh && !stale {
		s.mu.RUnlock()
		c.removeExpired(s, key)
		c.misses.Add(1)
		return nil, false, nil
	}
	res := cloneResult(entry.result)
	storedAt := entry.storedAt
	s.mu.RUnlock()

	if stale {
		res.Stale = true
		setResultTTL(res, 0)
		c.staleHits.Add(1)
	} else {
		ageResultTTL(res, now.Sub(storedAt))
		c.hits.Add(1)
	}
	return res, true, nil
}

// Put stores a defensive copy using the caller-supplied validated cache TTL.
func (c *MemoryCache) Put(ctx context.Context, req *Request, res *Result, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if res == nil || res.Message == nil {
		return errors.New("goreecloud dns: cannot cache nil result")
	}
	if ttl <= 0 {
		return errors.New("goreecloud dns: cache ttl must be positive")
	}
	key, hash, err := cacheKey(req)
	if err != nil {
		return err
	}

	now := c.now()
	entry := &memoryCacheEntry{
		result:    cloneResult(res),
		storedAt:  now,
		expiresAt: now.Add(ttl),
		negative:  isNegativeResponse(res.Message),
		sequence:  c.seq.Add(1),
	}
	entry.staleTo = entry.expiresAt
	if c.stale {
		entry.staleTo = entry.expiresAt.Add(c.staleTTL)
	}

	c.gate.RLock()
	defer c.gate.RUnlock()
	s := &c.shards[hash&c.mask]
	s.mu.Lock()
	if previous := s.entries[key]; previous != nil && previous.negative {
		c.negative.Add(^uint64(0))
	}
	s.entries[key] = entry
	if entry.negative {
		c.negative.Add(1)
	}
	if len(s.entries) > s.limit {
		c.evictOldestLocked(s, key)
	}
	s.mu.Unlock()
	c.puts.Add(1)
	return nil
}

// Flush removes all cached DNS state while excluding concurrent Get and Put.
func (c *MemoryCache) Flush(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.gate.Lock()
	defer c.gate.Unlock()
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		s.entries = make(map[string]*memoryCacheEntry)
		s.mu.Unlock()
	}
	c.negative.Store(0)
	return nil
}

// Stats returns runtime counters without exposing query names.
func (c *MemoryCache) Stats() CacheStats {
	c.gate.RLock()
	defer c.gate.RUnlock()
	var entries uint64
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.RLock()
		entries += uint64(len(s.entries))
		s.mu.RUnlock()
	}
	return CacheStats{
		Hits: c.hits.Load(), Misses: c.misses.Load(), StaleHits: c.staleHits.Load(),
		Puts: c.puts.Load(), Evictions: c.evictions.Load(), NegativeEntries: c.negative.Load(), Entries: entries,
	}
}

func (c *MemoryCache) removeExpired(s *memoryCacheShard, key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.entries[key]
	if entry == nil || c.now().Before(entry.staleTo) {
		return
	}
	delete(s.entries, key)
	if entry.negative {
		c.negative.Add(^uint64(0))
	}
}

func (c *MemoryCache) evictOldestLocked(s *memoryCacheShard, protected string) {
	var oldestKey string
	var oldestSeq uint64 = ^uint64(0)
	for key, entry := range s.entries {
		if key == protected && len(s.entries) > 1 {
			continue
		}
		if entry.sequence < oldestSeq {
			oldestKey, oldestSeq = key, entry.sequence
		}
	}
	if oldestKey == "" {
		return
	}
	entry := s.entries[oldestKey]
	delete(s.entries, oldestKey)
	if entry.negative {
		c.negative.Add(^uint64(0))
	}
	c.evictions.Add(1)
}

func cacheKey(req *Request) (string, uint64, error) {
	if req == nil || req.Message == nil || len(req.Message.Question) == 0 {
		return "", 0, errors.New("goreecloud dns: cache request must contain a question")
	}
	q := req.Message.Question[0]
	clientIP := ""
	if req.ClientIP.IsValid() {
		clientIP = req.ClientIP.String()
	}
	// Keep identity and address in the conservative cache partition. Route and
	// split-horizon selection may depend on subnet context, so an otherwise
	// stable ClientID must not carry a cached answer across network locations.
	key := fmt.Sprintf("%s|%d|%d|id=%s|ip=%s", dns.Fqdn(q.Name), q.Qtype, q.Qclass, req.ClientID, clientIP)
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	return key, h.Sum64(), nil
}

func isNegativeResponse(msg *dns.Msg) bool {
	return msg != nil && (msg.Rcode == dns.RcodeNameError || (msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0))
}

func cloneResult(res *Result) *Result {
	if res == nil {
		return nil
	}
	copy := *res
	if res.Message != nil {
		copy.Message = res.Message.Copy()
	}
	return &copy
}

func ageResultTTL(res *Result, age time.Duration) {
	if res == nil || res.Message == nil || age <= 0 {
		return
	}
	seconds := uint32(age / time.Second)
	for _, section := range [][]dns.RR{res.Message.Answer, res.Message.Ns, res.Message.Extra} {
		for _, rr := range section {
			if rr == nil || rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			if rr.Header().Ttl > seconds {
				rr.Header().Ttl -= seconds
			} else {
				rr.Header().Ttl = 0
			}
		}
	}
}

func setResultTTL(res *Result, ttl uint32) {
	if res == nil || res.Message == nil {
		return
	}
	for _, section := range [][]dns.RR{res.Message.Answer, res.Message.Ns, res.Message.Extra} {
		for _, rr := range section {
			if rr != nil && rr.Header().Rrtype != dns.TypeOPT {
				rr.Header().Ttl = ttl
			}
	}
}
