package privacyshieldstatus

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	infrastructurestatus "github.com/AdguardTeam/AdGuardHome/goreecloud/status"
)

func TestReadyEvidenceRemainsPendingAcceptance(t *testing.T) {
	snapshot := SnapshotFromEvidence(
		time.Date(2026, 9, 7, 14, 50, 0, 0, time.UTC),
		infrastructurestatus.RuntimeEvidence{
			ResolverRunning:   true,
			FilteringReady:    true,
			EncryptedDNSReady: true,
			DNSPolicyReady:    true,
		},
	)

	if snapshot.SchemaVersion != 1 || snapshot.State != "development" {
		t.Fatalf("unexpected development status: %#v", snapshot)
	}
	if snapshot.Producer.AdapterID != "dns" || snapshot.Producer.Product != "GoreeCloud DNS" || snapshot.Producer.RuntimeAuthority != "GoreeCloud/goreecloud-dns" || snapshot.Producer.AdapterContractVersion != 1 {
		t.Fatalf("unexpected producer identity: %#v", snapshot.Producer)
	}
	if len(snapshot.Capabilities) != 1 || snapshot.Capabilities[0] != (Capability{ID: "dns-privacy", State: "pending-acceptance"}) {
		t.Fatalf("unexpected Privacy Shield capability status: %#v", snapshot.Capabilities)
	}
	if snapshot.Acceptance.ProductionApproved || !snapshot.Acceptance.RuntimeAcceptanceRequired {
		t.Fatal("Development evidence must not bypass Privacy Shield runtime acceptance")
	}
	if snapshot.ValidUntil != "" {
		t.Fatal("unapproved Development status must not synthesize a protected validity window")
	}
}

func TestResolverUnavailableFailsClosed(t *testing.T) {
	snapshot := SnapshotFromEvidence(time.Now(), infrastructurestatus.RuntimeEvidence{})
	if snapshot.State != "unavailable" || snapshot.Capabilities[0].State != "unavailable" {
		t.Fatalf("resolver outage must fail closed: %#v", snapshot)
	}
}

func TestPrivacyCapabilityInactiveWhenFilteringOrPolicyUnavailable(t *testing.T) {
	for _, evidence := range []infrastructurestatus.RuntimeEvidence{
		{ResolverRunning: true, FilteringReady: false, DNSPolicyReady: true},
		{ResolverRunning: true, FilteringReady: true, DNSPolicyReady: false},
	} {
		snapshot := SnapshotFromEvidence(time.Now(), evidence)
		if snapshot.State != "attention" || snapshot.Capabilities[0].State != "inactive" {
			t.Fatalf("incomplete privacy enforcement evidence must require attention: %#v", snapshot)
		}
	}
}

func TestSerializedStatusIsPrivacyMinimized(t *testing.T) {
	snapshot := SnapshotFromEvidence(
		time.Date(2026, 9, 7, 14, 55, 0, 0, time.UTC),
		infrastructurestatus.RuntimeEvidence{ResolverRunning: true, FilteringReady: true, DNSPolicyReady: true},
	)
	payload, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal Privacy Shield status: %v", err)
	}

	var object map[string]any
	if err = json.Unmarshal(payload, &object); err != nil {
		t.Fatalf("decode Privacy Shield status: %v", err)
	}
	allowed := map[string]bool{
		"schema_version": true,
		"producer": true,
		"generated_at": true,
		"state": true,
		"capabilities": true,
		"privacy": true,
		"acceptance": true,
	}
	for key := range object {
		if !allowed[key] {
			t.Fatalf("unexpected top-level status field %q", key)
		}
	}

	lower := strings.ToLower(string(payload))
	for _, forbidden := range []string{"query_name", "client_identifier", "source_address", "credential", "private_key", "certificate_material", "filter_content"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("privacy status leaked forbidden field marker %q: %s", forbidden, payload)
		}
	}
}
