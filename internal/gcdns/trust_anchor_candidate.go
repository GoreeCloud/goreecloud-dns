package gcdns

import (
	"errors"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// AuthenticatedTrustAnchorCandidate is the boundary between future external
// trust-anchor acquisition and Beacon lifecycle state. The acquisition layer
// must authenticate the source before constructing this value. Beacon still
// requires hold-down completion and explicit approval before activation.
type AuthenticatedTrustAnchorCandidate struct {
	Source        string
	AcquiredAt    time.Time
	Authenticated bool
	Anchors       []*dns.DS
}

func ValidateAuthenticatedTrustAnchorCandidate(candidate AuthenticatedTrustAnchorCandidate) error {
	if !candidate.Authenticated {
		return errors.New("goreecloud dns: trust-anchor candidate source is not authenticated")
	}
	if strings.TrimSpace(candidate.Source) == "" {
		return errors.New("goreecloud dns: authenticated trust-anchor candidate source is required")
	}
	if candidate.AcquiredAt.IsZero() {
		return errors.New("goreecloud dns: authenticated trust-anchor candidate acquisition time is required")
	}
	records := trustAnchorRecordsFromDS(candidate.Anchors)
	if err := validateTrustAnchorRecords(records); err != nil {
		return err
	}
	return nil
}

// BeginAuthenticatedTrustAnchorHoldDown validates an already authenticated
// candidate and starts timing evidence. It does not stage or approve anchors.
func BeginAuthenticatedTrustAnchorHoldDown(candidate AuthenticatedTrustAnchorCandidate, holdDown time.Duration) (TrustAnchorRolloverState, error) {
	if err := ValidateAuthenticatedTrustAnchorCandidate(candidate); err != nil {
		return TrustAnchorRolloverState{}, err
	}
	return NewTrustAnchorRolloverState(candidate.Anchors, candidate.AcquiredAt, holdDown)
}
