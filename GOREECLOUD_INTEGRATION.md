# GoreeCloud DNS Integration Boundary

GoreeCloud DNS currently retains the AdGuard Home-derived runtime as its DNS data plane. This file defines the GoreeCloud-owned control/observability boundary without claiming that the upstream-derived runtime has been replaced.

## Infrastructure Status v1

`./goreecloud/statuscmd` emits a strict, privacy-minimized status envelope compatible with GoreeCloud Manager's Infrastructure Status v1 consumer.

```bash
go run ./goreecloud/statuscmd
```

Set `GOREECLOUD_DNS_STATUS_FILE=/path/to/dns-status.json` to enable the local runtime handoff. The AdGuard Home `home` package then refreshes the file every 30 seconds using the same owner-only atomic writer used by the standalone emitter.

The in-process adapter currently proves only bounded lifecycle facts:

- resolver running: derived from the existing DNS server `IsRunning` state;
- filtering ready: verified when the resolver is running because filter initialization is a prerequisite of DNS startup;
- DNS policy ready: verified on the same startup invariant;
- encrypted DNS ready: deliberately remains unverified until a lifecycle-safe adapter can read TLS-manager readiness without exposing certificate/configuration material.

A running resolver therefore reports `partial`, not `ready`, until encrypted-DNS evidence is independently wired and accepted. Runtime evidence still does not set `production_approved`; target-environment acceptance remains a separate gate.

## Privacy boundary

The status contract must never expose DNS query logs, client addresses, client identifiers, upstream credentials, private configuration, filter contents, raw logs, TLS private keys, certificate material, or personal records. Manager receives only coarse capability states.

The in-process publisher creates no listener and performs no network access. It is opt-in through `GOREECLOUD_DNS_STATUS_FILE` and writes only the Infrastructure Status v1 envelope to the configured local filesystem boundary.

## Next implementation slice

1. Add a lifecycle-safe TLS-manager boolean adapter so encrypted-DNS readiness can be proven without exporting certificate details.
2. Add target-environment DNS correctness and privacy acceptance tests.
3. Add upgrade, rollback, and resolver-outage acceptance tests.
4. Keep `production_approved` false until those target-environment gates pass.

## Licensing

This GoreeCloud integration code remains inside this repository's existing GPL-3.0 licensing boundary. No upstream-derived code is relicensed by this work.
