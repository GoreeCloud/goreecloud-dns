package gcdns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

type fakePolicyFilterListSignedAcquirer struct {
	snapshots []PolicyFilterListSnapshot
	errs      []error
	calls     int
}

func (f *fakePolicyFilterListSignedAcquirer) AcquireSigned(
	_ context.Context,
	_ PolicyFilterListAcquisitionConfig,
	_ PolicyFilterListTrustedKeys,
	_ time.Time,
) (PolicyFilterListSnapshot, error) {
	index := f.calls
	f.calls++
	if index < len(f.errs) && f.errs[index] != nil {
		return PolicyFilterListSnapshot{}, f.errs[index]
	}
	if index >= len(f.snapshots) {
		return PolicyFilterListSnapshot{}, errors.New("fake acquirer: no snapshot")
	}
	return clonePolicyFilterListSnapshot(f.snapshots[index]), nil
}

func TestPolicyFilterListRefreshControllerSuccessAndSchedule(t *testing.T) {
	now := time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC)
	lifecycle := NewPolicyFilterListLifecycle()
	acquirer := &fakePolicyFilterListSignedAcquirer{
		snapshots: []PolicyFilterListSnapshot{refreshTestSnapshot(1, now.Add(-time.Minute), now.Add(2*time.Hour), "one.example\n")},
	}
	controller, err := NewPolicyFilterListRefreshController(
		lifecycle,
		acquirer,
		PolicyFilterListAcquisitionConfig{},
		nil,
		PolicyFilterListRefreshPolicy{
			RefreshInterval: time.Hour,
			InitialBackoff:  time.Minute,
			MaxBackoff:      10 * time.Minute,
			OfflineGrace:    30 * time.Minute,
		},
	)
	if err != nil {
		t.Fatalf("construct refresh controller: %v", err)
	}

	result, err := controller.Refresh(context.Background(), now)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !result.Attempted || !result.Applied {
		t.Fatalf("expected attempted+applied result: %+v", result)
	}
	if result.ConsecutiveFailures != 0 || !result.NextAttempt.Equal(now.Add(time.Hour)) {
		t.Fatalf("unexpected success schedule: %+v", result)
	}
	if result.Availability != PolicyFilterListAvailabilityFresh || result.ActiveSequence != 1 {
		t.Fatalf("unexpected active state: %+v", result)
	}

	skipped, err := controller.Refresh(context.Background(), now.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("skip before due: %v", err)
	}
	if skipped.Attempted || skipped.Applied || acquirer.calls != 1 {
		t.Fatalf("refresh before due should not acquire: result=%+v calls=%d", skipped, acquirer.calls)
	}
}

func TestPolicyFilterListRefreshControllerTreatsExactSnapshotAsSuccessfulNoop(t *testing.T) {
	now := time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC)
	snapshot := refreshTestSnapshot(2, now.Add(-time.Minute), now.Add(2*time.Hour), "same.example\n")
	lifecycle := NewPolicyFilterListLifecycle()
	if err := lifecycle.Apply(snapshot, now); err != nil {
		t.Fatalf("seed active snapshot: %v", err)
	}
	acquirer := &fakePolicyFilterListSignedAcquirer{snapshots: []PolicyFilterListSnapshot{snapshot}}
	controller, err := NewPolicyFilterListRefreshController(
		lifecycle,
		acquirer,
		PolicyFilterListAcquisitionConfig{},
		nil,
		PolicyFilterListRefreshPolicy{RefreshInterval: time.Hour, InitialBackoff: time.Minute, MaxBackoff: 10 * time.Minute},
	)
	if err != nil {
		t.Fatalf("construct refresh controller: %v", err)
	}

	result, err := controller.Refresh(context.Background(), now)
	if err != nil {
		t.Fatalf("exact no-op refresh: %v", err)
	}
	if !result.Attempted || result.Applied || result.ConsecutiveFailures != 0 {
		t.Fatalf("exact immutable snapshot should be successful no-op: %+v", result)
	}
	if !result.NextAttempt.Equal(now.Add(time.Hour)) {
		t.Fatalf("successful no-op should use normal interval: %+v", result)
	}
}

func TestPolicyFilterListRefreshControllerBackoff(t *testing.T) {
	now := time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC)
	acquirer := &fakePolicyFilterListSignedAcquirer{errs: []error{errors.New("offline"), errors.New("offline")}}
	controller, err := NewPolicyFilterListRefreshController(
		NewPolicyFilterListLifecycle(),
		acquirer,
		PolicyFilterListAcquisitionConfig{},
		nil,
		PolicyFilterListRefreshPolicy{
			RefreshInterval: time.Hour,
			InitialBackoff:  5 * time.Minute,
			MaxBackoff:      20 * time.Minute,
		},
	)
	if err != nil {
		t.Fatalf("construct refresh controller: %v", err)
	}

	first, err := controller.Refresh(context.Background(), now)
	if err == nil {
		t.Fatal("expected first acquisition failure")
	}
	if first.ConsecutiveFailures != 1 || !first.NextAttempt.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("unexpected first backoff: %+v", first)
	}

	skipped, err := controller.Refresh(context.Background(), now.Add(4*time.Minute))
	if err != nil || skipped.Attempted || acquirer.calls != 1 {
		t.Fatalf("expected skipped retry before due: result=%+v err=%v calls=%d", skipped, err, acquirer.calls)
	}

	secondAt := now.Add(5 * time.Minute)
	second, err := controller.Refresh(context.Background(), secondAt)
	if err == nil {
		t.Fatal("expected second acquisition failure")
	}
	if second.ConsecutiveFailures != 2 || !second.NextAttempt.Equal(secondAt.Add(10*time.Minute)) {
		t.Fatalf("unexpected second backoff: %+v", second)
	}
}

func TestPolicyFilterListRefreshControllerOfflineGrace(t *testing.T) {
	now := time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC)
	expires := now.Add(10 * time.Minute)
	lifecycle := NewPolicyFilterListLifecycle()
	if err := lifecycle.Apply(refreshTestSnapshot(3, now.Add(-time.Minute), expires, "three.example\n"), now); err != nil {
		t.Fatalf("seed active snapshot: %v", err)
	}
	controller, err := NewPolicyFilterListRefreshController(
		lifecycle,
		&fakePolicyFilterListSignedAcquirer{},
		PolicyFilterListAcquisitionConfig{},
		nil,
		PolicyFilterListRefreshPolicy{
			RefreshInterval: time.Hour,
			InitialBackoff:  time.Minute,
			MaxBackoff:      5 * time.Minute,
			OfflineGrace:    30 * time.Minute,
		},
	)
	if err != nil {
		t.Fatalf("construct refresh controller: %v", err)
	}

	if _, availability, ok := controller.UsableSnapshot(expires.Add(15 * time.Minute)); !ok || availability != PolicyFilterListAvailabilityOfflineGrace {
		t.Fatalf("expected explicit offline grace, got availability=%q ok=%v", availability, ok)
	}
	if _, availability, ok := controller.UsableSnapshot(expires.Add(30 * time.Minute)); ok || availability != PolicyFilterListAvailabilityUnavailable {
		t.Fatalf("expected fail-closed expiry after grace, got availability=%q ok=%v", availability, ok)
	}
}

func TestPolicyFilterListRefreshControllerRejectsInvalidPolicy(t *testing.T) {
	_, err := NewPolicyFilterListRefreshController(
		NewPolicyFilterListLifecycle(),
		&fakePolicyFilterListSignedAcquirer{},
		PolicyFilterListAcquisitionConfig{},
		nil,
		PolicyFilterListRefreshPolicy{RefreshInterval: time.Hour, InitialBackoff: 2 * time.Minute, MaxBackoff: time.Minute},
	)
	if err == nil {
		t.Fatal("expected invalid backoff policy to fail")
	}
}

func refreshTestSnapshot(sequence uint64, issuedAt, expiresAt time.Time, content string) PolicyFilterListSnapshot {
	body := []byte(content)
	digest := sha256.Sum256(body)
	return PolicyFilterListSnapshot{
		Provenance: PolicyFilterListProvenance{
			SourceID:       "test-source",
			SourceURI:      "https://filters.example/list.txt",
			Publisher:      "GoreeCloud Test",
			Sequence:       sequence,
			IssuedAt:       issuedAt,
			ExpiresAt:      expiresAt,
			MetadataSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ContentSHA256:  hex.EncodeToString(digest[:]),
		},
		Content: body,
	}
}
