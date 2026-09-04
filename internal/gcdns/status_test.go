package gcdns

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"
)

type statusPolicy struct{}

func (statusPolicy) Evaluate(context.Context, *Request) (*Result, bool, error) {
	return nil, false, nil
}

type statusAuthority struct{}

func (statusAuthority) ResolveAuthoritative(context.Context, *Request) (*Result, bool, error) {
	return nil, false, nil
}

type statusCache struct{}

func (statusCache) Get(context.Context, *Request) (*Result, bool, error)        { return nil, false, nil }
func (statusCache) Put(context.Context, *Request, *Result, time.Duration) error { return nil }
func (statusCache) Flush(context.Context) error                                 { return nil }

type statusResolver struct{}

func (statusResolver) Resolve(context.Context, *Request) (*Result, error) { return nil, nil }

func validStatusSecurityConfig() SecurityConfig {
	return SecurityConfig{
		DNSSECValidation:    true,
		RebindingProtection: true,
		RecursionACLs:       []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		AdminACLs:           []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	}
}

func TestStatusSnapshotSeparatesReadinessFromAvailability(t *testing.T) {
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	pipeline := &Pipeline{
		Policy:    statusPolicy{},
		Authority: statusAuthority{},
		Cache:     statusCache{},
		Resolver:  statusResolver{},
	}

	got := pipeline.StatusSnapshot(now, validStatusSecurityConfig())
	if got.Schema != RuntimeStatusSchemaV1 || !got.GeneratedAt.Equal(now) {
		t.Fatalf("unexpected status identity: %+v", got)
	}
	if got.ProductionAuthority != ProductionAuthorityInherited {
		t.Fatalf("production authority = %q, want %q", got.ProductionAuthority, ProductionAuthorityInherited)
	}
	if got.ProductionCutoverAuthorized {
		t.Fatal("source status must not authorize production cutover")
	}
	if got.ConfigurationState != ConfigurationStateValid {
		t.Fatalf("configuration state = %q, want %q", got.ConfigurationState, ConfigurationStateValid)
	}
	if got.PipelineState != PipelineStateComplete {
		t.Fatalf("pipeline state = %q, want %q", got.PipelineState, PipelineStateComplete)
	}
	if got.Availability != AvailabilityUnknown || got.AvailabilityReason != AvailabilityReasonRuntimeHealthNotObserved {
		t.Fatalf("availability = (%q, %q), want fail-closed unknown evidence", got.Availability, got.AvailabilityReason)
	}
}

func TestStatusSnapshotFailsConfigurationAndPipelineReadinessClosed(t *testing.T) {
	got := (*Pipeline)(nil).StatusSnapshot(time.Now().UTC(), SecurityConfig{})
	if got.ConfigurationState != ConfigurationStateInvalid {
		t.Fatalf("configuration state = %q, want %q", got.ConfigurationState, ConfigurationStateInvalid)
	}
	if got.PipelineState != PipelineStateIncomplete {
		t.Fatalf("pipeline state = %q, want %q", got.PipelineState, PipelineStateIncomplete)
	}
	if got.Availability != AvailabilityUnknown {
		t.Fatalf("availability = %q, want %q", got.Availability, AvailabilityUnknown)
	}
}

func TestStatusSnapshotPrivacySafeFieldBoundary(t *testing.T) {
	got := (&Pipeline{}).StatusSnapshot(time.Now().UTC(), SecurityConfig{})
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("decode status fields: %v", err)
	}
	allowed := map[string]bool{
		"schema":                        true,
		"generated_at":                  true,
		"production_authority":          true,
		"production_cutover_authorized": true,
		"configuration_state":           true,
		"pipeline_state":                true,
		"availability":                  true,
		"availability_reason":           true,
	}
	if len(fields) != len(allowed) {
		t.Fatalf("status fields = %d, want exactly %d privacy-safe fields", len(fields), len(allowed))
	}
	for field := range fields {
		if !allowed[field] {
			t.Fatalf("unexpected status field %q", field)
		}
	}
}
