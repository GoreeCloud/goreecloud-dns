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

var goreecloudStatusPath string

// EnableGoreeCloudStatusPublisher enables the fork-only local status handoff
// when GOREECLOUD_DNS_STATUS_FILE is configured.  Main calls this before the
// DNS and TLS lifecycle exists, so this function only records the local target.
// The publisher itself is started after the TLS manager has been initialized.
func EnableGoreeCloudStatusPublisher() {
	goreecloudStatusPath = os.Getenv(goreecloudStatusFileEnv)
}

func startGoreeCloudStatusPublisher(tlsMgr *tlsManager) {
	if goreecloudStatusPath == "" {
		return
	}

	go runGoreeCloudStatusPublisher(
		goreecloudStatusPath,
		goreecloudStatusInterval,
		tlsMgr,
	)
}

func runGoreeCloudStatusPublisher(path string, interval time.Duration, tlsMgr *tlsManager) {
	publishGoreeCloudStatus(path, time.Now(), tlsMgr)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for now := range ticker.C {
		publishGoreeCloudStatus(path, now, tlsMgr)
	}
}

func publishGoreeCloudStatus(path string, now time.Time, tlsMgr *tlsManager) {
	snapshot := goreecloudstatus.SnapshotFromEvidence(now, goreecloudRuntimeEvidence(tlsMgr))
	if err := goreecloudstatus.WriteFile(path, snapshot); err != nil {
		slog.Warn("goreecloud status handoff failed", "error", err)
	}
}

// goreecloudRuntimeEvidence deliberately derives only coarse booleans from the
// existing DNS and TLS lifecycles.  A running resolver implies the filtering
// and policy engines were initialized because initDNS fails before server
// startup if those components cannot be constructed.
func goreecloudRuntimeEvidence(tlsMgr *tlsManager) goreecloudstatus.RuntimeEvidence {
	resolverRunning := isRunning()

	return goreecloudstatus.RuntimeEvidence{
		ResolverRunning:   resolverRunning,
		FilteringReady:    resolverRunning,
		EncryptedDNSReady: resolverRunning && goreecloudEncryptedDNSReady(tlsMgr),
		DNSPolicyReady:    resolverRunning,
	}
}

// goreecloudEncryptedDNSReady returns only a boolean and never copies or
// exports certificate material, private keys, server names, listener addresses,
// paths, or other TLS configuration.  ResolverRunning is checked by the caller,
// so configured encrypted-DNS listeners have already passed DNS startup.
func goreecloudEncryptedDNSReady(tlsMgr *tlsManager) bool {
	if tlsMgr == nil {
		return false
	}

	tlsMgr.mu.Lock()
	defer tlsMgr.mu.Unlock()

	extTLSConf := tlsMgr.extTLSConf
	if extTLSConf == nil || !extTLSConf.Enabled {
		return false
	}

	// DNSCrypt is initialized as part of the DNS server configuration.  If the
	// resolver is running and the DNSCrypt listener was configured, startup has
	// already validated its resolver configuration.
	if extTLSConf.PortDNSCrypt != 0 && extTLSConf.DNSCryptConfigFile != "" {
		return true
	}

	// DoH, DoT, and DoQ require a successfully loaded TLS pair in addition to
	// an enabled listener.  Keep the actual pair and configuration private.
	if tlsMgr.tlsConf == nil || tlsMgr.tlsCert == nil {
		return false
	}

	return extTLSConf.PortHTTPS != 0 ||
		extTLSConf.PortDNSOverTLS != 0 ||
		extTLSConf.PortDNSOverQUIC != 0
}
