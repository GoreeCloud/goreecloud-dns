package gcdns

import (
	"testing"
	"time"
)

func TestAuthenticatedTrustAnchorCandidateRequiresAuthenticatedSource(t *testing.T) {
	candidate := AuthenticatedTrustAnchorCandidate{
		Source:     "authenticated-root-anchor-feed",
		AcquiredAt: time.Now().UTC(),
		Anchors:    RootTrustAnchors(),
	}
	if err := ValidateAuthenticatedTrustAnchorCandidate(candidate); err == nil {
		t.Fatal("unauthenticated candidate unexpectedly accepted")
	}
}

func TestBeginAuthenticatedTrustAnchorHoldDownDoesNotActivateCandidate(t *testing.T) {
	now := time.Date(2026, 8, 26, 20, 0, 0, 0, time.UTC)
	candidate := AuthenticatedTrustAnchorCandidate{
		Source:        "authenticated-root-anchor-feed",
		AcquiredAt:    now,
		Authenticated: true,
		Anchors:       RootTrustAnchors(),
	}
	state, err := BeginAuthenticatedTrustAnchorHoldDown(candidate, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := TrustAnchorCandidateHoldDownComplete(state, now)
	if err != nil {
		t.Fatal(err)
	}
	if complete {
		t.Fatal("newly observed candidate unexpectedly completed hold-down")
	}
}

func TestAuthenticatedCandidateRejectsMissingSource(t *testing.T) {
	candidate := AuthenticatedTrustAnchorCandidate{
		AcquiredAt:    time.Now().UTC(),
		Authenticated: true,
		Anchors:       RootTrustAnchors(),
	}
	if err := ValidateAuthenticatedTrustAnchorCandidate(candidate); err == nil {
		t.Fatal("candidate without source unexpectedly accepted")
	}
}
