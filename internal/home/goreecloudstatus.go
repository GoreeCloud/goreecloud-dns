package home

import (
	"log/slog"
	"os"
	"time"

	privacyshieldstatus "github.com/AdguardTeam/AdGuardHome/goreecloud/privacyshieldstatus"
	goreecloudstatus "github.com/AdguardTeam/AdGuardHome/goreecloud/status"
)

const (
	goreecloudStatusFileEnv              = "GOREECLOUD_DNS_STATUS_FILE"
	goreecloudPrivacyShieldStatusFileEnv = "GOREECLOUD_DNS_PRIVACY_SHIELD_STATUS_FILE"
	goreecloudStatusInterval             = 30 * time.Second
)

// EnableGoreeCloudStatusPublisher enables the fork-only local status handoffs
// when either status path is configured.  Infrastructure Status and Privacy
// Shield status remain separate files and contracts.  The publisher creates no
// listener and performs no network access.
func EnableGoreeCloudStatusPublisher() {
	statusPath := os.Getenv(goreecloudStatusFileEnv)
	privacyShieldPath := os.Getenv(goreecloudPrivacyShieldStatusFileEnv)
	if statusPath == "" && privacyShieldPath == "" {
		return
	}

	go runGoreeCloudStatusPublisher(statusPath, privacyShieldPath, goreecloudStatusInterval)
}

func runGoreeCloudStatusPublisher(statusPath, privacyShieldPath string, interval time.Duration) {
	publishGoreeCloudStatus(statusPath, privacyShieldPath, time.Now())

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for now := range ticker.C {
		publishGoreeCloudStatus(statusPath, privacyShieldPath, now)
	}
}

func publishGoreeCloudStatus(statusPath, privacyShieldPath string, now time.Time) {
	evidence := goreecloudRuntimeEvidence()

	if statusPath != "" {
		snapshot := goreecloudstatus.SnapshotFromEvidence(now, evidence)
		if err := goreecloudstatus.WriteFile(statusPath, snapshot); err != nil {
			slog.Warn("goreecloud status handoff failed", "error", err)
		}
	}

	if privacyShieldPath != "" {
		snapshot := privacyshieldstatus.SnapshotFromEvidence(now, evidence)
		if err := privacyshieldstatus.WriteFile(privacyShieldPath, snapshot); err != nil {
			slog.Warn("goreecloud Privacy Shield status handoff failed", "error", err)
		}
	}
}

// goreecloudRuntimeEvidence deliberately derives only coarse booleans from the
// DNS server lifecycle.  A running resolver implies the filtering and policy
// engines were initialized because initDNS fails before server startup if those
// components cannot be constructed.  Encrypted DNS remains unverified here:
// proving certificate/TLS runtime readiness requires a lifecycle-safe adapter to
// tlsManager and must not be inferred from certificate or configuration data.
func goreecloudRuntimeEvidence() goreecloudstatus.RuntimeEvidence {
	resolverRunning := isRunning()

	return goreecloudstatus.RuntimeEvidence{
		ResolverRunning:   resolverRunning,
		FilteringReady:    resolverRunning,
		EncryptedDNSReady: false,
		DNSPolicyReady:    resolverRunning,
	}
}
