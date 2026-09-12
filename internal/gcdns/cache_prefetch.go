package gcdns

import (
	"context"
	"errors"
	"sync"
	"time"
)

// PrefetchConfig controls proactive cache refresh selection.
type PrefetchConfig struct {
	// MinimumHits is the minimum number of successful cache hits before an
	// entry becomes eligible for proactive refresh.
	MinimumHits uint64

	// RefreshWithin selects entries whose remaining positive TTL is at or below
	// this threshold. It must be positive when prefetch is enabled.
	RefreshWithin time.Duration
}

// PrefetchCandidate identifies a popular cache entry that should be refreshed
// before expiration. Request is a defensive copy of the original query.
type PrefetchCandidate struct {
	Request      *Request
	Hits         uint64
	RemainingTTL time.Duration
}

type prefetchRecord struct {
	request *Request
	hits    uint64
}

// PrefetchCache wraps the native memory cache with popularity tracking and
// deterministic prefetch candidate selection. It does not perform network
// refreshes itself; the resolver scheduler owns that work.
type PrefetchCache struct {
	cache *MemoryCache
	conf  PrefetchConfig

	mu      sync.Mutex
	records map[string]*prefetchRecord
}

// NewPrefetchCache creates a first-party prefetch tracker around cache.
func NewPrefetchCache(cache *MemoryCache, conf PrefetchConfig) (*PrefetchCache, error) {
	if cache == nil {
		return nil, errors.New("goreecloud dns: prefetch cache requires a memory cache")
	}
	if conf.MinimumHits == 0 {
		return nil, errors.New("goreecloud dns: prefetch minimum hits must be positive")
	}
	if conf.RefreshWithin <= 0 {
		return nil, errors.New("goreecloud dns: prefetch refresh window must be positive")
	}

	return &PrefetchCache{
		cache:   cache,
		conf:    conf,
		records: make(map[string]*prefetchRecord),
	}, nil
}

// Get implements Cache while tracking successful fresh-cache hits.
func (p *PrefetchCache) Get(ctx context.Context, req *Request) (*Result, bool, error) {
	res, ok, err := p.cache.Get(ctx, req)
	if err != nil || !ok || res == nil || res.Stale {
		return res, ok, err
	}

	key, keyErr := cacheKey(req)
	if keyErr != nil {
		return nil, false, keyErr
	}
	p.mu.Lock()
	record := p.records[key]
	if record == nil {
		record = &prefetchRecord{request: cloneRequest(req)}
		p.records[key] = record
	}
	record.hits++
	p.mu.Unlock()

	return res, true, nil
}

// Put implements Cache and preserves accumulated popularity for refreshed
// entries while ensuring there is a request template for future refresh work.
func (p *PrefetchCache) Put(ctx context.Context, req *Request, res *Result, ttl time.Duration) error {
	if err := p.cache.Put(ctx, req, res, ttl); err != nil {
		return err
	}

	key, err := cacheKey(req)
	if err != nil {
		return err
	}
	p.mu.Lock()
	if record := p.records[key]; record != nil {
		record.request = cloneRequest(req)
	} else {
		p.records[key] = &prefetchRecord{request: cloneRequest(req)}
	}
	p.mu.Unlock()

	return nil
}

// Flush implements Cache and clears both cached data and popularity state.
func (p *PrefetchCache) Flush(ctx context.Context) error {
	if err := p.cache.Flush(ctx); err != nil {
		return err
	}
	p.mu.Lock()
	p.records = make(map[string]*prefetchRecord)
	p.mu.Unlock()

	return nil
}

// Candidates returns up to limit popular fresh entries that are approaching
// expiration. A non-positive limit means no explicit result limit.
func (p *PrefetchCache) Candidates(ctx context.Context, limit int) ([]PrefetchCandidate, error) {
	p.mu.Lock()
	records := make([]prefetchRecord, 0, len(p.records))
	for _, record := range p.records {
		if record.hits >= p.conf.MinimumHits && record.request != nil {
			records = append(records, prefetchRecord{request: cloneRequest(record.request), hits: record.hits})
		}
	}
	p.mu.Unlock()

	candidates := make([]PrefetchCandidate, 0, len(records))
	for _, record := range records {
		res, ok, err := p.cache.Get(ctx, record.request)
		if err != nil {
			return nil, err
		}
		if !ok || res == nil || res.Stale || res.CacheTTL <= 0 || res.CacheTTL > p.conf.RefreshWithin {
			continue
		}
		candidates = append(candidates, PrefetchCandidate{
			Request:      cloneRequest(record.request),
			Hits:         record.hits,
			RemainingTTL: res.CacheTTL,
		})
		if limit > 0 && len(candidates) >= limit {
			break
		}
	}

	return candidates, nil
}

func cloneRequest(req *Request) *Request {
	if req == nil {
		return nil
	}
	clone := *req
	if req.Message != nil {
		clone.Message = req.Message.Copy()
	}

	return &clone
}
