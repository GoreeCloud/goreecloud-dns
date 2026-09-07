package gcdns

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// PolicyFilterListSignedAcquirer is the narrow signed-acquisition boundary used
// by refresh orchestration. PolicyFilterListAcquirer satisfies this interface.
type PolicyFilterListSignedAcquirer interface {
	AcquireSigned(
		ctx context.Context,
		config PolicyFilterListAcquisitionConfig,
		trustedKeys PolicyFilterListTrustedKeys,
		now time.Time,
	) (PolicyFilterListSnapshot, error)
}

// PolicyFilterListRefreshPolicy controls periodic refresh, bounded retry, and
// the explicit local offline-grace window for an already authenticated active
// snapshot. OfflineGrace may be zero to fail closed immediately at expiry.
type PolicyFilterListRefreshPolicy struct {
	RefreshInterval time.Duration
	InitialBackoff  time.Duration
	MaxBackoff      time.Duration
	OfflineGrace    time.Duration
}

// PolicyFilterListAvailability describes whether the active immutable snapshot
// is currently usable by a caller of UsableSnapshot.
type PolicyFilterListAvailability string

const (
	PolicyFilterListAvailabilityUnavailable  PolicyFilterListAvailability = "unavailable"
	PolicyFilterListAvailabilityFresh        PolicyFilterListAvailability = "fresh"
	PolicyFilterListAvailabilityOfflineGrace PolicyFilterListAvailability = "offline-grace"
)

var ErrPolicyFilterListRefreshInProgress = errors.New("goreecloud dns: filter-list refresh is already in progress")

// PolicyFilterListRefreshState is a privacy-safe orchestration snapshot. It
// intentionally excludes list content, URLs, signing keys, and acquisition
// error strings.
type PolicyFilterListRefreshState struct {
	NextAttempt         time.Time
	LastAttempt         time.Time
	LastSuccess         time.Time
	ConsecutiveFailures uint32
	InFlight            bool
	Availability        PolicyFilterListAvailability
	ActiveSequence      uint64
}

// PolicyFilterListRefreshResult reports one Refresh call without turning a
// skipped/not-yet-due call into an error.
type PolicyFilterListRefreshResult struct {
	PolicyFilterListRefreshState
	Attempted bool
	Applied   bool
}

// PolicyFilterListRefreshController schedules signed list acquisition without
// owning a goroutine or production listener. Callers decide when to invoke
// Refresh and may use NextAttempt to integrate with their runtime scheduler.
//
// A failed refresh never mutates the active lifecycle snapshot. Offline grace
// only affects UsableSnapshot for a previously authenticated snapshot; it does
// not relax signature, digest, source-identity, sequence, or acquisition checks.
type PolicyFilterListRefreshController struct {
	mu          sync.Mutex
	lifecycle   *PolicyFilterListLifecycle
	acquirer    PolicyFilterListSignedAcquirer
	config      PolicyFilterListAcquisitionConfig
	trustedKeys PolicyFilterListTrustedKeys
	policy      PolicyFilterListRefreshPolicy

	nextAttempt         time.Time
	lastAttempt         time.Time
	lastSuccess         time.Time
	consecutiveFailures uint32
	inFlight            bool
}

func NewPolicyFilterListRefreshController(
	lifecycle *PolicyFilterListLifecycle,
	acquirer PolicyFilterListSignedAcquirer,
	config PolicyFilterListAcquisitionConfig,
	trustedKeys PolicyFilterListTrustedKeys,
	policy PolicyFilterListRefreshPolicy,
) (*PolicyFilterListRefreshController, error) {
	if lifecycle == nil {
		return nil, errors.New("goreecloud dns: filter-list lifecycle is required")
	}
	if acquirer == nil {
		return nil, errors.New("goreecloud dns: filter-list signed acquirer is required")
	}
	if policy.RefreshInterval <= 0 {
		return nil, errors.New("goreecloud dns: filter-list refresh interval must be positive")
	}
	if policy.InitialBackoff <= 0 {
		return nil, errors.New("goreecloud dns: filter-list initial backoff must be positive")
	}
	if policy.MaxBackoff < policy.InitialBackoff {
		return nil, errors.New("goreecloud dns: filter-list max backoff must be at least the initial backoff")
	}
	if policy.OfflineGrace < 0 {
		return nil, errors.New("goreecloud dns: filter-list offline grace cannot be negative")
	}

	configCopy := config
	configCopy.AllowedHosts = append([]string(nil), config.AllowedHosts...)
	return &PolicyFilterListRefreshController{
		lifecycle:   lifecycle,
		acquirer:    acquirer,
		config:      configCopy,
		trustedKeys: clonePolicyFilterListTrustedKeys(trustedKeys),
		policy:      policy,
	}, nil
}

// Refresh performs at most one signed acquisition when the refresh is due.
// Failures use capped exponential backoff; success returns to RefreshInterval.
func (c *PolicyFilterListRefreshController) Refresh(ctx context.Context, now time.Time) (PolicyFilterListRefreshResult, error) {
	if c == nil {
		return PolicyFilterListRefreshResult{}, errors.New("goreecloud dns: filter-list refresh controller is required")
	}
	if ctx == nil {
		return PolicyFilterListRefreshResult{}, errors.New("goreecloud dns: filter-list refresh context is required")
	}
	if err := ctx.Err(); err != nil {
		return c.result(now, false, false), err
	}

	c.mu.Lock()
	if c.inFlight {
		c.mu.Unlock()
		return c.result(now, false, false), ErrPolicyFilterListRefreshInProgress
	}
	if !c.nextAttempt.IsZero() && now.Before(c.nextAttempt) {
		c.mu.Unlock()
		return c.result(now, false, false), nil
	}
	c.inFlight = true
	c.lastAttempt = now
	c.mu.Unlock()

	snapshot, err := c.acquirer.AcquireSigned(ctx, c.config, c.trustedKeys, now)
	applied := false
	if err == nil {
		if !c.matchesActive(snapshot) {
			err = c.lifecycle.Apply(snapshot, now)
			applied = err == nil
		}
	}

	c.mu.Lock()
	c.inFlight = false
	if err != nil {
		if c.consecutiveFailures < ^uint32(0) {
			c.consecutiveFailures++
		}
		c.nextAttempt = now.Add(policyFilterListRefreshBackoff(c.policy, c.consecutiveFailures))
	} else {
		c.consecutiveFailures = 0
		c.lastSuccess = now
		c.nextAttempt = now.Add(c.policy.RefreshInterval)
	}
	c.mu.Unlock()

	return c.result(now, true, applied), err
}

func (c *PolicyFilterListRefreshController) matchesActive(snapshot PolicyFilterListSnapshot) bool {
	active, ok := c.lifecycle.Active()
	if !ok {
		return false
	}
	return active.Provenance.SourceID == snapshot.Provenance.SourceID &&
		active.Provenance.Sequence == snapshot.Provenance.Sequence &&
		strings.EqualFold(active.Provenance.MetadataSHA256, snapshot.Provenance.MetadataSHA256) &&
		strings.EqualFold(active.Provenance.ContentSHA256, snapshot.Provenance.ContentSHA256)
}

// UsableSnapshot returns a defensive copy of the active snapshot only while it
// is fresh or inside the explicitly configured offline-grace window. A clock
// rollback before IssuedAt fails closed. At or after ExpiresAt+OfflineGrace the
// snapshot is unavailable even though lifecycle history still retains it.
func (c *PolicyFilterListRefreshController) UsableSnapshot(now time.Time) (PolicyFilterListSnapshot, PolicyFilterListAvailability, bool) {
	if c == nil || c.lifecycle == nil {
		return PolicyFilterListSnapshot{}, PolicyFilterListAvailabilityUnavailable, false
	}
	snapshot, ok := c.lifecycle.Active()
	if !ok || now.Before(snapshot.Provenance.IssuedAt) {
		return PolicyFilterListSnapshot{}, PolicyFilterListAvailabilityUnavailable, false
	}
	if now.Before(snapshot.Provenance.ExpiresAt) {
		return snapshot, PolicyFilterListAvailabilityFresh, true
	}
	if c.policy.OfflineGrace > 0 && now.Before(snapshot.Provenance.ExpiresAt.Add(c.policy.OfflineGrace)) {
		return snapshot, PolicyFilterListAvailabilityOfflineGrace, true
	}
	return PolicyFilterListSnapshot{}, PolicyFilterListAvailabilityUnavailable, false
}

// State returns privacy-safe refresh timing and active-sequence information.
func (c *PolicyFilterListRefreshController) State(now time.Time) PolicyFilterListRefreshState {
	if c == nil {
		return PolicyFilterListRefreshState{Availability: PolicyFilterListAvailabilityUnavailable}
	}
	c.mu.Lock()
	state := PolicyFilterListRefreshState{
		NextAttempt:         c.nextAttempt,
		LastAttempt:         c.lastAttempt,
		LastSuccess:         c.lastSuccess,
		ConsecutiveFailures: c.consecutiveFailures,
		InFlight:            c.inFlight,
	}
	c.mu.Unlock()

	if snapshot, availability, ok := c.UsableSnapshot(now); ok {
		state.Availability = availability
		state.ActiveSequence = snapshot.Provenance.Sequence
	} else {
		state.Availability = PolicyFilterListAvailabilityUnavailable
	}
	return state
}

func (c *PolicyFilterListRefreshController) result(now time.Time, attempted, applied bool) PolicyFilterListRefreshResult {
	return PolicyFilterListRefreshResult{
		PolicyFilterListRefreshState: c.State(now),
		Attempted:                    attempted,
		Applied:                      applied,
	}
}

func policyFilterListRefreshBackoff(policy PolicyFilterListRefreshPolicy, failures uint32) time.Duration {
	backoff := policy.InitialBackoff
	for step := uint32(1); step < failures && backoff < policy.MaxBackoff; step++ {
		if backoff > policy.MaxBackoff/2 {
			return policy.MaxBackoff
		}
		backoff *= 2
	}
	if backoff > policy.MaxBackoff {
		return policy.MaxBackoff
	}
	return backoff
}

func clonePolicyFilterListTrustedKeys(keys PolicyFilterListTrustedKeys) PolicyFilterListTrustedKeys {
	if keys == nil {
		return nil
	}
	cloned := make(PolicyFilterListTrustedKeys, len(keys))
	for keyID, publicKey := range keys {
		cloned[keyID] = append([]byte(nil), publicKey...)
	}
	return cloned
}
