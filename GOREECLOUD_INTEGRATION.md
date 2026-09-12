# GoreeCloud DNS Integration Boundary

GoreeCloud DNS is the authoritative GoreeCloud product for DNS runtime truth. The current development foundation still retains an AdGuard Home-derived compatibility data plane and may use configured external recursive/forwarding components during migration, but those implementation details are transitional and do not replace GoreeCloud DNS as the product/runtime authority.

## Infrastructure Status v1

`./goreecloud/statuscmd` emits a strict, privacy-minimized GoreeCloud DNS infrastructure-status envelope for controlled operational consumption.

```bash
go run ./goreecloud/statuscmd
```

Set `GOREECLOUD_DNS_STATUS_FILE=/path/to/dns-status.json` to enable the local runtime handoff. The DNS `home` package then refreshes the file every 30 seconds using the same atomic writer used by the standalone emitter. The writer requests POSIX mode `0600`; on platforms such as Windows where POSIX mode bits are not the native access-control boundary, the configured directory must have an approved ACL that limits access to the intended producer and consumer.

The in-process adapter currently proves only bounded lifecycle facts:

- resolver running: derived from the current DNS server `IsRunning` state;
- filtering ready: verified when the resolver is running because filter initialization is a prerequisite of DNS startup on the retained compatibility path;
- DNS policy ready: verified on the same startup invariant;
- encrypted DNS ready: deliberately remains unverified until a lifecycle-safe adapter can read TLS-manager readiness without exposing certificate/configuration material.

A running resolver therefore reports `partial`, not `ready`, until encrypted-DNS evidence is independently wired and accepted. Runtime evidence still does not set `production_approved`; target-environment acceptance remains a separate gate.

The envelope identifies `GoreeCloud/goreecloud-dns` as runtime authority. It must not encode an inherited implementation, upstream project, forwarder, recursive component, or data-plane nickname as the GoreeCloud authority.

## Privacy boundary

The status contract must never expose DNS query logs, client addresses, client identifiers, upstream credentials, private configuration, filter contents, raw logs, TLS private keys, certificate material, or personal records. Operational consumers receive only coarse capability states.

The in-process publisher creates no listener and performs no network access. It is opt-in through `GOREECLOUD_DNS_STATUS_FILE` and writes only the Infrastructure Status v1 envelope to the configured local filesystem boundary.

Infrastructure Status is not the GoreeCloud Privacy Shield status contract. A Privacy Shield integration may reuse the same coarse runtime evidence, but it must project that evidence into the separately governed Privacy Shield schema and must not alias, relabel, or merge the two envelopes.

## Current acceptance boundary

This branch provides Development-only status evidence. It does not:

- make GoreeCloud Manager authoritative for DNS runtime state;
- transfer DNS execution or configuration authority away from GoreeCloud DNS;
- make the inherited compatibility data plane a permanent GoreeCloud architecture;
- establish Privacy Shield, Wardveil Security, Everkeep, Identity, Mesh, or Glaze UI acceptance;
- approve production deployment or DNS cutover;
- establish Stable status.

## Next implementation slice

1. Add a lifecycle-safe TLS-manager boolean adapter so encrypted-DNS readiness can be proven without exporting certificate details.
2. Add target-environment DNS correctness and privacy acceptance tests.
3. Add upgrade, rollback, and resolver-outage acceptance tests.
4. Keep `production_approved` false until those target-environment gates pass.
5. Reuse the coarse evidence through separate platform-specific projections only where the applicable platform contract permits it.

## Licensing

This GoreeCloud integration code remains inside this repository's existing GPL-3.0 licensing boundary. No upstream-derived code is relicensed by this work.
