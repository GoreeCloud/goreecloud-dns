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
	payload, marshalErr := json.MarshalIndent(snapshot, "", "  ")
	if marshalErr != nil {
		fatal(marshalErr)
	}
	payload = append(payload, '\n')

	path := os.Getenv("GOREECLOUD_DNS_STATUS_FILE")
	if path == "" {
		_, _ = os.Stdout.Write(payload)
		return
	}
	if mkdirErr := os.MkdirAll(filepath.Dir(path), 0o750); mkdirErr != nil {
		fatal(mkdirErr)
	}
	tmp := path + ".tmp"
	if writeErr := os.WriteFile(tmp, payload, 0o640); writeErr != nil {
		fatal(writeErr)
	}
	if renameErr := os.Rename(tmp, path); renameErr != nil {
		fatal(renameErr)
	}
}

func fatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "goreecloud-dns status: %v\n", err)
	os.Exit(1)
}
