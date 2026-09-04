package status

import (
	"testing"
	"time"
)

func TestDevelopmentSnapshotDoesNotExposeDNSData(t *testing.T) {
	snapshot := DevelopmentSnapshot(time.Date(2026, 9, 1, 16, 0, 0, 0, time.UTC))
	if snapshot.SchemaVersion != 1 || snapshot.Producer.ServiceID != "goreecloud-dns" {
		t.Fatal("unexpected GoreeCloud DNS contract identity")
	}
	if snapshot.State != "development" || snapshot.Acceptance.ProductionApproved {
		t.Fatal("development adapter must not claim production readiness")
	}
	if !snapshot.Acceptance.RuntimeAcceptanceRequired {
		t.Fatal("runtime acceptance must remain explicit")
	}
	if snapshot.Privacy.ContainsCredentials || snapshot.Privacy.ContainsPersonalData || snapshot.Privacy.ContainsRawLogs || snapshot.Privacy.ContainsNetworkIdentifiers || snapshot.Privacy.ContainsQueryData || snapshot.Privacy.ContainsCertificateMaterial {
		t.Fatal("DNS status must exclude sensitive and query data")
	}
}
