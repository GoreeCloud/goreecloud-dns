package gcdns

import "time"

const RuntimeStatusSchemaV1 = "goreecloud-beacon-runtime-status/v1"

const (
	ProductionAuthorityInherited = "inherited"

	ConfigurationStateValid   = "valid"
	ConfigurationStateInvalid = "invalid"

	PipelineStateComplete   = "complete"
	PipelineStateIncomplete = "incomplete"

	AvailabilityUnknown = "unknown"

	AvailabilityReasonRuntimeHealthNotObserved = "runtime_health_not_observed"
)

// RuntimeStatus is a privacy-safe snapshot of Beacon candidate runtime wiring.
// It intentionally contains no DNS queries, client identifiers, domain names,
// policy contents, trust-anchor material, credentials, private zones, upstream
// addresses, or raw diagnostics.
//
// Configuration and pipeline state are not service-availability claims. Until
// an authoritative live health source exists, availability remains unknown and
// must not be promoted into connectivity, privacy, security, or continuity
// state by downstream consumers.
type RuntimeStatus struct {
	Schema                      string    `json:"schema"`
	GeneratedAt                 time.Time `json:"generated_at"`
	ProductionAuthority         string    `json:"production_authority"`
	ProductionCutoverAuthorized bool      `json:"production_cutover_authorized"`
	ConfigurationState          string    `json:"configuration_state"`
	PipelineState               string    `json:"pipeline_state"`
	Availability                string    `json:"availability"`
	AvailabilityReason          string    `json:"availability_reason"`
}

// StatusSnapshot reports only facts that the local Beacon candidate can own.
// A valid configuration and a fully wired pipeline are useful readiness facts,
// but neither proves that a live resolver listener is serving successfully.
func (p *Pipeline) StatusSnapshot(now time.Time, cfg SecurityConfig) RuntimeStatus {
	status := RuntimeStatus{
		Schema:                      RuntimeStatusSchemaV1,
		GeneratedAt:                 now,
		ProductionAuthority:         ProductionAuthorityInherited,
		ProductionCutoverAuthorized: false,
		ConfigurationState:          ConfigurationStateInvalid,
		PipelineState:               PipelineStateIncomplete,
		Availability:                AvailabilityUnknown,
		AvailabilityReason:          AvailabilityReasonRuntimeHealthNotObserved,
	}

	if cfg.Validate() == nil {
		status.ConfigurationState = ConfigurationStateValid
	}
	if p != nil && p.Policy != nil && p.Authority != nil && p.Cache != nil && p.Resolver != nil {
		status.PipelineState = PipelineStateComplete
	}

	return status
}
