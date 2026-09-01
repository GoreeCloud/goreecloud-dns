package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	goreecloudstatus "github.com/AdguardTeam/AdGuardHome/goreecloud/status"
)

func main() {
	snapshot := goreecloudstatus.DevelopmentSnapshot(time.Now())
	payload, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		fatal(err)
	}
	payload = append(payload, '\n')

	path := os.Getenv("GOREECLOUD_DNS_STATUS_FILE")
	if path == "" {
		_, _ = os.Stdout.Write(payload)
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		fatal(err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o640); err != nil {
		fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "goreecloud-dns status: %v\n", err)
	os.Exit(1)
}
