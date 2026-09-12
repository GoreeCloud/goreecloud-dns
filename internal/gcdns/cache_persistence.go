package gcdns

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/miekg/dns"
)

const persistentCacheVersion = 1

type persistentCacheFile struct {
	Version int                    `json:"version"`
	SavedAt time.Time              `json:"saved_at"`
	Entries []persistentCacheEntry `json:"entries"`
}

type persistentCacheEntry struct {
	Key       string    `json:"key"`
	Message   string    `json:"message"`
	Source    string    `json:"source"`
	ExpiresAt time.Time `json:"expires_at"`
	StaleAt   time.Time `json:"stale_at"`
	CreatedAt time.Time `json:"created_at"`
	Negative  bool      `json:"negative"`
}

// SavePersistent writes the current usable cache state atomically with owner-only
// file permissions. The caller must explicitly provide a persistence path.
func (c *MemoryCache) SavePersistent(path string) error {
	if path == "" {
		return errors.New("goreecloud dns: persistent cache path is required")
	}

	c.gate.RLock()
	defer c.gate.RUnlock()

	now := c.now()
	file := persistentCacheFile{Version: persistentCacheVersion, SavedAt: now}
	for i := range c.shards {
		shard := &c.shards[i]
		shard.mu.RLock()
		for key, entry := range shard.entries {
			if !c.usable(entry, now) || entry.result == nil || entry.result.Message == nil {
				continue
			}

			wire, err := entry.result.Message.Pack()
			if err != nil {
				shard.mu.RUnlock()
				return fmt.Errorf("goreecloud dns: pack persistent cache entry: %w", err)
			}
			file.Entries = append(file.Entries, persistentCacheEntry{
				Key:       key,
				Message:   base64.StdEncoding.EncodeToString(wire),
				Source:    entry.result.Source,
				ExpiresAt: entry.expiresAt,
				StaleAt:   entry.staleAt,
				CreatedAt: entry.createdAt,
				Negative:  entry.negative,
			})
		}
		shard.mu.RUnlock()
	}

	data, err := json.Marshal(file)
	if err != nil {
		return fmt.Errorf("goreecloud dns: marshal persistent cache: %w", err)
	}

	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("goreecloud dns: create persistent cache directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".goreecloud-dns-cache-*")
	if err != nil {
		return fmt.Errorf("goreecloud dns: create persistent cache temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("goreecloud dns: write persistent cache: %w", err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("goreecloud dns: replace persistent cache: %w", err)
	}

	return nil
}

// LoadPersistent restores usable entries from a previously saved cache file.
// Expired records outside the configured stale window are discarded.
func (c *MemoryCache) LoadPersistent(path string) (int, error) {
	if path == "" {
		return 0, errors.New("goreecloud dns: persistent cache path is required")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("goreecloud dns: read persistent cache: %w", err)
	}

	var file persistentCacheFile
	if err = json.Unmarshal(data, &file); err != nil {
		return 0, fmt.Errorf("goreecloud dns: decode persistent cache: %w", err)
	}
	if file.Version != persistentCacheVersion {
		return 0, fmt.Errorf("goreecloud dns: unsupported persistent cache version %d", file.Version)
	}

	c.gate.Lock()
	defer c.gate.Unlock()

	now := c.now()
	loaded := 0
	for _, stored := range file.Entries {
		usableUntil := stored.ExpiresAt
		if c.serveStale {
			usableUntil = stored.StaleAt
		}
		if !now.Before(usableUntil) {
			continue
		}

		wire, decodeErr := base64.StdEncoding.DecodeString(stored.Message)
		if decodeErr != nil {
			return loaded, fmt.Errorf("goreecloud dns: decode persistent cache message: %w", decodeErr)
		}
		msg := new(dns.Msg)
		if unpackErr := msg.Unpack(wire); unpackErr != nil {
			return loaded, fmt.Errorf("goreecloud dns: unpack persistent cache message: %w", unpackErr)
		}

		entry := &memoryCacheEntry{
			result:    &Result{Message: msg, Source: stored.Source},
			expiresAt: stored.ExpiresAt,
			staleAt:   stored.StaleAt,
			createdAt: stored.CreatedAt,
			negative:  stored.Negative,
		}
		shard := c.shard(stored.Key)
		shard.mu.Lock()
		if old, exists := shard.entries[stored.Key]; exists {
			c.decrementEntryStats(old)
		}
		shard.entries[stored.Key] = entry
		c.incrementEntryStats(entry)
		c.enforceLimit(shard, stored.Key)
		shard.mu.Unlock()
		loaded++
	}

	return loaded, nil
}
