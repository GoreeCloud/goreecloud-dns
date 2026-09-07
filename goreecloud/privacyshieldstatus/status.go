// Package privacyshieldstatus projects privacy-minimized GoreeCloud DNS runtime
// evidence into the separately governed GoreeCloud Privacy Shield status v1
// contract.  It does not change DNS runtime authority or production acceptance.
package privacyshieldstatus

import (
	"time"

	infrastructurestatus "github.com/AdguardTeam/AdGuardHome/goreecloud/status"
)

const SchemaVersion = 1

type Producer struct {
	AdapterID              string `json:"adapter_id"`
	Product                string `json:"product"`
	RuntimeAuthority       string `json:"runtime_authority"`
	AdapterContractVersion int    `json:"adapter_contract_version"`
}

type Capability struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

type Privacy struct {
	RawPrivateActivityIncluded bool `json:"raw_private_activity_included"`
	ContainsCredentials        bool `json:"contains_credentials"`
	ContainsIdentifiers        bool `json:"contains_identifiers"`
}

type Acceptance struct {
	RuntimeAcceptanceRequired bool `json:"runtime_acceptance_required"`
	ProductionApproved        bool `json:"production_approved"`
}

type Snapshot struct {
	SchemaVersion int          `json:"schema_version"`
	Producer      Producer     `json:"producer"`
	GeneratedAt   string       `json:"generated_at"`
	ValidUntil    string       `json:"valid_until,omitempty"`
	State         string       `json:"state"`
	Capabilities  []Capability `json:"capabilities"`
	Privacy       Privacy      `json:"privacy"`
	Acceptance    Acceptance   `json:"acceptance"`
}

// SnapshotFromEvidence maps only the coarse booleans already permitted by the
// GoreeCloud DNS Infrastructure Status boundary.  Healthy Development evidence
// remains pending acceptance; this function intentionally has no path to
// "protected", "active", or production_approved=true.
func SnapshotFromEvidence(now time.Time, evidence infrastructurestatus.RuntimeEvidence) Snapshot {
	state := "development"
	capabilityState := "pending-acceptance"

	switch {
	case !evidence.ResolverRunning:
		state = "unavailable"
		capabilityState = "unavailable"
	case !evidence.FilteringReady || !evidence.DNSPolicyReady:
		state = "attention"
		capabilityState = "inactive"
	}

	return Snapshot{
		SchemaVersion: SchemaVersion,
		Producer: Producer{
			AdapterID:              "dns",
			Product:                "GoreeCloud DNS",
			RuntimeAuthority:       "GoreeCloud/goreecloud-dns",
			AdapterContractVersion: 1,
		},
		GeneratedAt: now.UTC().Format(time.RFC3339),
		State:       state,
		Capabilities: []Capability{
			{ID: "dns-privacy", State: capabilityState},
		},
		Privacy: Privacy{},
		Acceptance: Acceptance{
			RuntimeAcceptanceRequired: true,
			ProductionApproved:        false,
		},
	}
}
