# Upstream Provenance

## Origin

GoreeCloud DNS is maintained as a fork of AdGuard Home.

- Upstream project: AdGuard Home
- Upstream repository: `AdguardTeam/AdGuardHome`
- GoreeCloud repository: `GoreeCloud/goreecloud-dns`
- Development model: GoreeCloud-maintained open-source fork with a controlled fork-to-native transition

## Maintenance Principle

The upstream project remains an important source of mature DNS behavior, security fixes, protocol handling, compatibility improvements, and implementation knowledge. GoreeCloud will preserve a documented upstream relationship while progressively introducing GoreeCloud-specific architecture, user experience, integrations, and security controls.

Upstream changes must not be merged blindly. Each synchronization should be reviewed for:

- Security impact.
- DNS behavior changes.
- Configuration migration effects.
- API changes.
- Frontend conflicts with Glaze UI work.
- Changes to defaults or telemetry.
- Dependency changes.
- Licensing or attribution changes.
- Build and release implications.

## Fork-to-Native Direction

Inherited components may be replaced when doing so provides meaningful improvement in ownership, privacy, maintainability, interoperability, security, or long-term independence.

A native replacement must not be treated as an improvement merely because it is GoreeCloud-written. Mature inherited behavior should remain until replacement code has equivalent or better validation and recovery characteristics.

## Attribution and License

Applicable upstream copyright, license, notice, source-distribution, and attribution requirements must be preserved. Exact license obligations must be reviewed before each public release and whenever upstream licensing changes.

## Production Boundary

Upstream synchronization and GoreeCloud development in this repository do not authorize a production DNS migration. Production cutover requires separate validation and acceptance.
