package home

import (
	"log/slog"
	"os"
	"time"

	goreecloudstatus "github.com/AdguardTeam/AdGuardHome/goreecloud/status"
)

const (
	goreecloudStatusFileEnv  = "GOREECLOUD_DNS_STATUS_FILE"
	goreecloudStatusInterval = 30 * time.Second
)

// EnableGoreeCloudStatusPublisher enables the fork-only local status handoff
// when GOREECLOUD_DNS_STATUS_FILE is configured.  It creates no listener and
// performs no network access.
func EnableGoreeCloudStatusPublisher() {
	path := os.Getenv(goreecloudStatusFileEnv)
	if path == "" {
		return
	}

	go runGoreeCloudStatusPublisher(path, goreecloudStatusInterval)
}

func runGoreeCloudStatusPublisher(path string, interval time.Duration) {
	publishGoreeCloudStatus(path, time.Now())

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for now := range ticker.C {
		publishGoreeCloudStatus(path, now)
	}
}

func publishGoreeCloudStatus(path string, now time.Time) {
	snapshot := goreecloudstatus.SnapshotFromEvidence(now, goreecloudRuntimeEvidence())
	if err := goreecloudstatus.WriteFile(path, snapshot); err != nil {
		slog.Warn("goreecloud status handoff failed", "error", err)
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
