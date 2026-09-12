package gcdns

import (
	"testing"
	"time"
)

func TestTrustAnchorRolloverHoldDownDoesNotActivateEarly(t *testing.T) {
	start := time.Date(2026, 8, 26, 20, 0, 0, 0, time.UTC)
	state, err := NewTrustAnchorRolloverState(RootTrustAnchors(), start, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := TrustAnchorCandidateHoldDownComplete(state, start.Add(29*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if complete {
		t.Fatal("hold-down completed before deadline")
	}
}

func TestTrustAnchorRolloverHoldDownCompletesAtDeadline(t *testing.T) {
	start := time.Date(2026, 8, 26, 20, 0, 0, 0, time.UTC)
	holdDown := 30 * 24 * time.Hour
	state, err := NewTrustAnchorRolloverState(RootTrustAnchors(), start, holdDown)
	if err != nil {
		t.Fatal(err)
	}
	state, err = ObserveTrustAnchorCandidate(state, RootTrustAnchors(), start.Add(10*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	complete, err := TrustAnchorCandidateHoldDownComplete(state, start.Add(holdDown))
	if err != nil {
		t.Fatal(err)
	}
	if !complete {
		t.Fatal("hold-down did not complete at deadline")
	}
}

func TestTrustAnchorRolloverRejectsChangedCandidate(t *testing.T) {
	start := time.Date(2026, 8, 26, 20, 0, 0, 0, time.UTC)
	state, err := NewTrustAnchorRolloverState(RootTrustAnchors(), start, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	candidate := RootTrustAnchors()[:1]
	if _, err := ObserveTrustAnchorCandidate(state, candidate, start.Add(time.Hour)); err == nil {
		t.Fatal("changed trust-anchor candidate unexpectedly continued existing hold-down")
	}
}

func TestTrustAnchorRolloverRejectsClockRollback(t *testing.T) {
	start := time.Date(2026, 8, 26, 20, 0, 0, 0, time.UTC)
	state, err := NewTrustAnchorRolloverState(RootTrustAnchors(), start, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	state, err = ObserveTrustAnchorCandidate(state, RootTrustAnchors(), start.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ObserveTrustAnchorCandidate(state, RootTrustAnchors(), start.Add(time.Hour)); err == nil {
		t.Fatal("backward clock movement unexpectedly accepted")
	}
	if _, err := TrustAnchorCandidateHoldDownComplete(state, start.Add(time.Hour)); err == nil {
		t.Fatal("hold-down evaluation accepted a clock earlier than persisted last_seen_at")
	}
}

func TestTrustAnchorRolloverRejectsInvalidDuration(t *testing.T) {
	start := time.Date(2026, 8, 26, 20, 0, 0, 0, time.UTC)
	if _, err := NewTrustAnchorRolloverState(RootTrustAnchors(), start, 0); err == nil {
		t.Fatal("zero hold-down duration unexpectedly accepted")
	}
}
