package gcdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestStageApprovedTrustAnchorCandidateRequiresExplicitFingerprint(t *testing.T) {
	now := time.Date(2026, 8, 27, 4, 0, 0, 0, time.UTC)
	store, err := NewTrustAnchorStore(t.TempDir()+"/anchors.json", func() time.Time { return now })
	if err != nil { t.Fatal(err) }
	state := BootstrapTrustAnchorState(now)

	anchors := RootTrustAnchors()
	candidateAnchors := make([]*dns.DS, 0, len(anchors))
	for _, anchor := range anchors {
		copy := *anchor
		candidateAnchors = append(candidateAnchors, &copy)
	}
	candidateAnchors[0].Digest = candidateAnchors[0].Digest[:len(candidateAnchors[0].Digest)-1] + "0"
	candidate := AuthenticatedTrustAnchorCandidate{Source: "authenticated-test-source", AcquiredAt: now, Authenticated: true, Anchors: candidateAnchors}
	fingerprint, err := trustAnchorFingerprint(trustAnchorRecordsFromDS(candidateAnchors))
	if err != nil { t.Fatal(err) }
	review := TrustAnchorTransitionReview{CandidateFingerprint: fingerprint, EvidenceSource: candidate.Source, ReviewedAt: now.Format(time.RFC3339Nano), HoldDownComplete: true, ManualApprovalReady: true}

	if _, err := StageApprovedTrustAnchorCandidate(store, state, candidate, review, "wrong"); err == nil {
		t.Fatal("mismatched explicit fingerprint unexpectedly staged candidate")
	}
	staged, err := StageApprovedTrustAnchorCandidate(store, state, candidate, review, fingerprint)
	if err != nil { t.Fatal(err) }
	if staged.Pending == nil || staged.Pending.Fingerprint != fingerprint {
		t.Fatalf("candidate was not staged exactly: %+v", staged.Pending)
	}
	if sameTrustAnchorSet(staged.Active, staged.Pending.Anchors) {
		t.Fatal("staging unexpectedly activated the candidate")
	}
}

func TestStageApprovedTrustAnchorCandidateRejectsUnreadyReview(t *testing.T) {
	now := time.Date(2026, 8, 27, 4, 0, 0, 0, time.UTC)
	store, err := NewTrustAnchorStore(t.TempDir()+"/anchors.json", func() time.Time { return now })
	if err != nil { t.Fatal(err) }
	candidate := AuthenticatedTrustAnchorCandidate{Source: "authenticated-test-source", AcquiredAt: now, Authenticated: true, Anchors: RootTrustAnchors()}
	fingerprint, err := trustAnchorFingerprint(trustAnchorRecordsFromDS(candidate.Anchors))
	if err != nil { t.Fatal(err) }
	review := TrustAnchorTransitionReview{CandidateFingerprint: fingerprint}
	if _, err := StageApprovedTrustAnchorCandidate(store, BootstrapTrustAnchorState(now), candidate, review, fingerprint); err == nil {
		t.Fatal("unready review unexpectedly staged candidate")
	}
}
