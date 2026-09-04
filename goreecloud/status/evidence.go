package status

import "time"

const (
	stateReady       = "ready"
	statePartial     = "partial"
	stateUnavailable = "unavailable"

	capabilityVerified    = "verified"
	capabilityAttention   = "attention"
	capabilityUnavailable = "unavailable"
)

// RuntimeEvidence is intentionally coarse. It is designed to be populated by
// in-process AdGuard Home state without carrying queries, client identifiers,
// addresses, credentials, logs, configuration values, or certificate data.
type RuntimeEvidence struct {
	ResolverRunning   bool
	FilteringReady    bool
	EncryptedDNSReady bool
	DNSPolicyReady    bool
}

// SnapshotFromEvidence converts bounded runtime evidence into Infrastructure
// Status v1. Operational evidence can make capabilities verified, but it does
// not bypass GoreeCloud runtime acceptance or production approval.
func SnapshotFromEvidence(now time.Time, evidence RuntimeEvidence) Snapshot {
	snapshot := DevelopmentSnapshot(now)

	if !evidence.ResolverRunning {
		snapshot.State = stateUnavailable
		snapshot.Capabilities = []Capability{
			{ID: "resolver", State: capabilityUnavailable},
			{ID: "filtering", State: capabilityUnavailable},
			{ID: "encrypted-dns", State: capabilityUnavailable},
			{ID: "dns-policy", State: capabilityUnavailable},
		}
		return snapshot
	}

	snapshot.State = stateReady
	snapshot.Capabilities = []Capability{
		{ID: "resolver", State: capabilityVerified},
		{ID: "filtering", State: evidenceState(evidence.FilteringReady)},
		{ID: "encrypted-dns", State: evidenceState(evidence.EncryptedDNSReady)},
		{ID: "dns-policy", State: evidenceState(evidence.DNSPolicyReady)},
	}
	if !evidence.FilteringReady || !evidence.EncryptedDNSReady || !evidence.DNSPolicyReady {
		snapshot.State = statePartial
	}

	return snapshot
}

func evidenceState(ok bool) string {
	if ok {
		return capabilityVerified
	}
	return capabilityAttention
}
