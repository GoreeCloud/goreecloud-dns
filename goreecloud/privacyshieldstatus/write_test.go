package privacyshieldstatus

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	infrastructurestatus "github.com/AdguardTeam/AdGuardHome/goreecloud/status"
)

func TestWriteFileAtomicallyWritesSeparatePrivacyStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "privacy", "dns-privacy-status.json")
	snapshot := SnapshotFromEvidence(
		time.Date(2026, 9, 7, 15, 0, 0, 0, time.UTC),
		infrastructurestatus.RuntimeEvidence{ResolverRunning: true, FilteringReady: true, DNSPolicyReady: true},
	)

	if err := WriteFile(path, snapshot); err != nil {
		t.Fatalf("write Privacy Shield status: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat Privacy Shield status: %v", err)
	}
	if runtime.GOOS != "windows" {
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("Privacy Shield status permissions = %o, want 600", got)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read Privacy Shield status: %v", err)
	}
	var decoded Snapshot
	if err = json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode Privacy Shield status: %v", err)
	}
	if decoded.State != "development" || decoded.Producer.AdapterID != "dns" || decoded.Capabilities[0].State != "pending-acceptance" {
		t.Fatalf("unexpected decoded Privacy Shield status: %#v", decoded)
	}
}

func TestWriteFileRejectsEmptyPath(t *testing.T) {
	if err := WriteFile("", SnapshotFromEvidence(time.Now(), infrastructurestatus.RuntimeEvidence{})); err == nil {
		t.Fatal("expected empty Privacy Shield status path rejection")
	}
}
