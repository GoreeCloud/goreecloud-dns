# GoreeCloud DNS Integration Boundary

GoreeCloud DNS currently retains the AdGuard Home-derived runtime as its DNS data plane. This file defines the first GoreeCloud-owned control/observability boundary without claiming that the upstream-derived runtime has been replaced.

## Infrastructure Status v1

`./goreecloud/statuscmd` emits a strict, privacy-minimized status envelope compatible with GoreeCloud Manager's Infrastructure Status v1 consumer.

```bash
go run ./goreecloud/statuscmd
```

Set `GOREECLOUD_DNS_STATUS_FILE=/path/to/dns-status.json` to write the envelope atomically instead of printing it.

The initial adapter reports `development` with `pending` capabilities until it is wired to accepted runtime evidence. That is intentional: source presence alone must not become a false production-health claim.

## Privacy boundary

The status contract must never expose DNS query logs, client addresses, client identifiers, upstream credentials, private configuration, filter contents, raw logs, TLS private keys, certificate material, or personal records. Manager receives only coarse capability states.

## Next implementation slice

1. Derive resolver/filter/encrypted-DNS/policy state from bounded local runtime interfaces.
2. Normalize those results without query/client data.
3. Add fail-closed malformed-state tests.
4. Add target-environment DNS correctness, privacy, upgrade/rollback, and outage acceptance before any `production_approved` claim.

## Licensing

This GoreeCloud integration code remains inside this repository's existing GPL-3.0 licensing boundary. No upstream-derived code is relicensed by this work.
