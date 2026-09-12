package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	goreecloudstatus "github.com/AdguardTeam/AdGuardHome/goreecloud/status"
)

func main() {
	snapshot := goreecloudstatus.DevelopmentSnapshot(time.Now())
	path := os.Getenv("GOREECLOUD_DNS_STATUS_FILE")
	if path != "" {
		if err := goreecloudstatus.WriteFile(path, snapshot); err != nil {
			fatal(err)
		}
		return
	}

	payload, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		fatal(err)
	}
	payload = append(payload, '\n')
	_, _ = os.Stdout.Write(payload)
}

func fatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "goreecloud-dns status: %v\n", err)
	os.Exit(1)
}
