# GoreeCloud DNS Project Direction

## Role

GoreeCloud DNS is the planned client-facing DNS filtering, policy-enforcement, private service-discovery, and DNS security platform for GoreeCloud.

## Initial Architecture

```text
Approved client
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

GoreeCloud DNS owns client-facing filtering and policy. Unbound remains responsible for recursive resolution, caching, and DNSSEC validation unless a future approved architecture changes that boundary.

## Planned Product Areas

- Overview and DNS health.
- Query visibility and diagnostics.
- Protection and filtering.
- Clients and device policy.
- Private GoreeCloud services.
- Policy profiles.
- Upstream resolver configuration.
- Wardveil Security capabilities.
- Configuration and recovery settings.

## Policy Profiles

Initial planned profiles are Administrator, Personal, Family, Child, IoT, Guest, Infrastructure, and Custom.

Profiles may eventually control filtering strength, SafeSearch behavior, blocked service categories, schedules, custom rules, access to private GoreeCloud names, logging and privacy levels, encrypted DNS behavior, and threat protection.

## Platform Integrations

Planned integrations include:

- GoreeCloud Network for private connectivity and client identity context.
- GoreeCloud Manager for centralized operational visibility.
- GoreeCloud Monitor for DNS health and behavior validation.
- GoreeCloud Notify for outage and security notifications.
- GoreeCloud Backup for configuration and state protection.

## Migration Principle

The current production AdGuard Home service must remain operational throughout early development.

Migration must be performed through isolated deployment and comparison testing. Where technically appropriate, migration should preserve DNS rewrites, client definitions, filters, custom rules, allowlists, upstream configuration, privacy settings, and other approved operational configuration.

The current production deployment remains the rollback authority until GoreeCloud DNS completes acceptance and stabilization.

## Development Sequence

1. Stable maintained-fork foundation.
2. GoreeCloud product identity and build governance.
3. Glaze UI integration.
4. GoreeCloud Services and private DNS workflows.
5. Policy profiles and client organization.
6. Wardveil Security DNS capabilities.
7. Platform integrations.
8. Isolated runtime and migration validation.
9. Explicit production acceptance.
10. Controlled production cutover and rollback window.

## Non-Goal

The project is not intended to become a superficial rebrand. Upstream code should remain where it is mature and useful; inherited components should be replaced only when a GoreeCloud implementation produces a justified and validated improvement.
