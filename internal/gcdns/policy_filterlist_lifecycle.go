package gcdns

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

const maxPolicyFilterListRollbackSnapshots = 8

// PolicyFilterListProvenance binds one immutable filter-list snapshot to a
// reviewed source and metadata artifact. MetadataSHA256 identifies the reviewed
// metadata bytes; signature verification remains a separate acquisition-layer
// responsibility and is not inferred from this digest.
type PolicyFilterListProvenance struct {
	SourceID       string
	SourceURI      string
	Publisher      string
	Sequence       uint64
	IssuedAt       time.Time
	ExpiresAt      time.Time
	MetadataSHA256 string
	ContentSHA256  string
}

// PolicyFilterListSnapshot is an immutable, integrity-bound list candidate.
type PolicyFilterListSnapshot struct {
	Provenance PolicyFilterListProvenance
	Content    []byte
}

// PolicyFilterListLifecycle maintains one active immutable snapshot plus a
// bounded rollback history. It performs no network I/O and never treats a
// mutable URL as sufficient integrity evidence.
type PolicyFilterListLifecycle struct {
	mu      sync.RWMutex
	active  *PolicyFilterListSnapshot
	history []PolicyFilterListSnapshot
}

// NewPolicyFilterListLifecycle returns an empty lifecycle manager.
func NewPolicyFilterListLifecycle() *PolicyFilterListLifecycle {
	return &PolicyFilterListLifecycle{}
}

// Active returns a defensive copy of the active snapshot.
func (l *PolicyFilterListLifecycle) Active() (PolicyFilterListSnapshot, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.active == nil {
		return PolicyFilterListSnapshot{}, false
	}
	return clonePolicyFilterListSnapshot(*l.active), true
}

// Apply validates and activates a newer immutable snapshot. Updates for an
// existing source must increase Sequence strictly. The previous active snapshot
// is retained in bounded rollback history.
func (l *PolicyFilterListLifecycle) Apply(snapshot PolicyFilterListSnapshot, now time.Time) error {
	if err := validatePolicyFilterListSnapshot(snapshot, now); err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active != nil {
		if snapshot.Provenance.SourceID != l.active.Provenance.SourceID {
			return errors.New("goreecloud dns: filter-list source identity cannot change during lifecycle update")
		}
		if snapshot.Provenance.Sequence <= l.active.Provenance.Sequence {
			return fmt.Errorf(
				"goreecloud dns: filter-list sequence must increase: active=%d candidate=%d",
				l.active.Provenance.Sequence,
				snapshot.Provenance.Sequence,
			)
		}
		if strings.EqualFold(snapshot.Provenance.ContentSHA256, l.active.Provenance.ContentSHA256) {
			return errors.New("goreecloud dns: filter-list update reuses active content digest")
		}
		l.history = append(l.history, clonePolicyFilterListSnapshot(*l.active))
		if len(l.history) > maxPolicyFilterListRollbackSnapshots {
			l.history = append([]PolicyFilterListSnapshot(nil), l.history[len(l.history)-maxPolicyFilterListRollbackSnapshots:]...)
		}
	}
	candidate := clonePolicyFilterListSnapshot(snapshot)
	l.active = &candidate
	return nil
}

// Rollback activates a retained prior snapshot identified by exact content
// SHA-256. Expired snapshots are rejected. Rollback is explicit and does not
// silently fetch or reconstruct missing historical content.
func (l *PolicyFilterListLifecycle) Rollback(contentSHA256 string, now time.Time) error {
	digest, err := normalizePolicyFilterListSHA256(contentSHA256)
	if err != nil {
		return fmt.Errorf("goreecloud dns: rollback digest: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active == nil {
		return errors.New("goreecloud dns: no active filter-list snapshot to roll back")
	}
	for i := len(l.history) - 1; i >= 0; i-- {
		candidate := l.history[i]
		if !strings.EqualFold(candidate.Provenance.ContentSHA256, digest) {
			continue
		}
		if err := validatePolicyFilterListSnapshot(candidate, now); err != nil {
			return fmt.Errorf("goreecloud dns: retained rollback snapshot is not acceptable: %w", err)
		}
		current := clonePolicyFilterListSnapshot(*l.active)
		l.history = append(l.history[:i], l.history[i+1:]...)
		l.history = append(l.history, current)
		if len(l.history) > maxPolicyFilterListRollbackSnapshots {
			l.history = append([]PolicyFilterListSnapshot(nil), l.history[len(l.history)-maxPolicyFilterListRollbackSnapshots:]...)
		}
		restored := clonePolicyFilterListSnapshot(candidate)
		l.active = &restored
		return nil
	}
	return errors.New("goreecloud dns: requested rollback snapshot is not retained")
}

func validatePolicyFilterListSnapshot(snapshot PolicyFilterListSnapshot, now time.Time) error {
	p := snapshot.Provenance
	if strings.TrimSpace(p.SourceID) == "" {
		return errors.New("goreecloud dns: filter-list source ID is required")
	}
	parsed, err := url.Parse(strings.TrimSpace(p.SourceURI))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return errors.New("goreecloud dns: filter-list source URI must be an absolute credential-free HTTPS URL")
	}
	if strings.TrimSpace(p.Publisher) == "" {
		return errors.New("goreecloud dns: filter-list publisher is required")
	}
	if p.Sequence == 0 {
		return errors.New("goreecloud dns: filter-list sequence must be greater than zero")
	}
	if p.IssuedAt.IsZero() || p.ExpiresAt.IsZero() || !p.ExpiresAt.After(p.IssuedAt) {
		return errors.New("goreecloud dns: filter-list freshness window is invalid")
	}
	if now.Before(p.IssuedAt) {
		return errors.New("goreecloud dns: filter-list snapshot is not valid yet")
	}
	if !now.Before(p.ExpiresAt) {
		return errors.New("goreecloud dns: filter-list snapshot is expired")
	}
	if _, err := normalizePolicyFilterListSHA256(p.MetadataSHA256); err != nil {
		return fmt.Errorf("goreecloud dns: filter-list metadata digest: %w", err)
	}
	contentDigest, err := normalizePolicyFilterListSHA256(p.ContentSHA256)
	if err != nil {
		return fmt.Errorf("goreecloud dns: filter-list content digest: %w", err)
	}
	if len(snapshot.Content) == 0 {
		return errors.New("goreecloud dns: filter-list snapshot content is required")
	}
	if len(snapshot.Content) > maxPolicyFilterListBytes {
		return fmt.Errorf("goreecloud dns: filter-list snapshot exceeds %d bytes", maxPolicyFilterListBytes)
	}
	actual := sha256.Sum256(snapshot.Content)
	if hex.EncodeToString(actual[:]) != contentDigest {
		return errors.New("goreecloud dns: filter-list snapshot content digest mismatch")
	}
	return nil
}

func normalizePolicyFilterListSHA256(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != sha256.Size*2 {
		return "", errors.New("SHA-256 must contain exactly 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", errors.New("SHA-256 is not valid hexadecimal")
	}
	return value, nil
}

func clonePolicyFilterListSnapshot(snapshot PolicyFilterListSnapshot) PolicyFilterListSnapshot {
	clone := snapshot
	clone.Content = append([]byte(nil), snapshot.Content...)
	return clone
}
