# GoreeCloud DNS

GoreeCloud DNS is the planned client-facing DNS filtering, policy-enforcement, private service-discovery, and DNS security platform for GoreeCloud.

This repository is a GoreeCloud-maintained fork of AdGuard Home. The project begins from the mature AdGuard Home DNS foundation and will be progressively adapted into a distinct GoreeCloud product while preserving applicable upstream licensing, attribution, and source-availability obligations.

## Project Direction

GoreeCloud DNS is intended to provide:

- Network-wide advertisement and tracker blocking.
- Malicious-domain and threat-domain blocking.
- Client-specific DNS policies.
- Family and child policy profiles.
- Private GoreeCloud DNS records and service discovery.
- Query visibility and privacy-aware diagnostics.
- Upstream DNS management.
- Approved encrypted DNS capabilities.
- Integration with GoreeCloud Network, Manager, Monitor, Notify, and Backup.
- Wardveil Security capabilities for DNS security and policy enforcement.

## Architecture Boundary

GoreeCloud DNS is the client-facing DNS layer.

The initial architecture preserves Unbound as the recursive, caching, and DNSSEC-validating resolver:

```text
Approved clients
      |
      v
GoreeCloud DNS
      |
      v
   Unbound
      |
      v
Internet DNS authorities
```

GoreeCloud DNS replaces the long-term role currently performed by AdGuard Home; it does not replace Unbound unless a future approved architecture explicitly changes that responsibility.

## Development Model

The project follows a controlled fork-to-native transition:

```text
AdGuard Home
    -> GoreeCloud-maintained fork
    -> GoreeCloud-native interface and integrations
    -> increasingly independent internal architecture
    -> GoreeCloud-controlled DNS platform
```

Early development will prioritize stability, provenance, build validation, security, migration compatibility, and preservation of mature DNS behavior before major inherited subsystems are replaced.

## Design and Security

The GoreeCloud-controlled administration experience will use the **Glaze UI** design language.

Security-oriented DNS capabilities will be presented under **Wardveil Security by GoreeCloud** where appropriate and where the implementation provides the claimed protection.

## Production Safety

The current production AdGuard Home deployment remains authoritative until GoreeCloud DNS completes isolated validation, migration testing, backup and restore validation, security testing, and explicit production acceptance.

Development in this repository does not authorize production DNS cutover.

## Upstream

Upstream project: AdGuard Home  
Upstream repository: `AdguardTeam/AdGuardHome`

See [UPSTREAM.md](UPSTREAM.md) for provenance and maintenance expectations.

## License

This fork preserves the upstream project's applicable license and notices. See the repository license files and upstream provenance documentation before redistribution or release.
