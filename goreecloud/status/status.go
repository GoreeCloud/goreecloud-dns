// Package status defines the privacy-minimized GoreeCloud infrastructure status boundary.
package status

import "time"

const SchemaVersion = 1

type Producer struct {
	ServiceID        string `json:"service_id"`
	AdapterID        string `json:"adapter_id"`
	RuntimeAuthority string `json:"runtime_authority"`
}

type Privacy struct {
	ContainsCredentials         bool `json:"contains_credentials"`
	ContainsPersonalData        bool `json:"contains_personal_data"`
	ContainsRawLogs             bool `json:"contains_raw_logs"`
	ContainsNetworkIdentifiers  bool `json:"contains_network_identifiers"`
	ContainsQueryData           bool `json:"contains_query_data"`
	ContainsCertificateMaterial bool `json:"contains_certificate_material"`
}

type Acceptance struct {
	RuntimeAcceptanceRequired bool `json:"runtime_acceptance_required"`
	ProductionApproved        bool `json:"production_approved"`
}

type Capability struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

type Snapshot struct {
	SchemaVersion int          `json:"schema_version"`
	Producer      Producer     `json:"producer"`
	GeneratedAt   string       `json:"generated_at"`
	State         string       `json:"state"`
	Privacy       Privacy      `json:"privacy"`
	Acceptance    Acceptance   `json:"acceptance"`
	Capabilities  []Capability `json:"capabilities"`
}

// DevelopmentSnapshot is deliberately conservative until the adapter is wired to
// accepted GoreeCloud DNS runtime evidence.
func DevelopmentSnapshot(now time.Time) Snapshot {
	return Snapshot{
		SchemaVersion: SchemaVersion,
		Producer: Producer{
			ServiceID:        "goreecloud-dns",
			AdapterID:        "goreecloud-dns/status-v1",
			RuntimeAuthority: "GoreeCloud/AdGuardHomeDataPlane",
		},
		GeneratedAt: now.UTC().Format(time.RFC3339),
		State:       "development",
		Privacy:     Privacy{},
		Acceptance: Acceptance{
			RuntimeAcceptanceRequired: true,
			ProductionApproved:        false,
		},
		Capabilities: []Capability{
			{ID: "resolver", State: "pending"},
			{ID: "filtering", State: "pending"},
			{ID: "encrypted-dns", State: "pending"},
			{ID: "dns-policy", State: "pending"},
		},
	}
}
