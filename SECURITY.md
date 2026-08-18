# Security Policy

## Project Status

GoreeCloud DNS is foundational network infrastructure and is currently under development as a GoreeCloud-maintained fork of AdGuard Home.

The existing production AdGuard Home deployment remains authoritative until GoreeCloud DNS completes isolated testing, migration validation, backup and restore validation, security testing, and explicit production acceptance.

A successful source build or CI run does not authorize production DNS cutover.

## Security Requirements

Changes to GoreeCloud DNS should preserve or improve the following controls:

- No unrestricted public recursive resolver.
- Administrative access restricted to approved users and networks.
- Secrets separated from source-controlled configuration.
- Privacy-aware DNS query logging and retention.
- Secure dependency and update practices.
- Backup and restoration capability for required configuration and state.
- Validation of failure, restart, and invalid-configuration behavior.
- Preservation of independent network and application authorization boundaries for private GoreeCloud services.

## Wardveil Security

Security-focused GoreeCloud DNS capabilities may be presented under **Wardveil Security by GoreeCloud** only when the implementation and validation evidence support the claimed protection.

Potential areas include malicious-domain protection, DNS bypass detection, encrypted-DNS policy enforcement, suspicious-query indicators, and security-event integration.

## Reporting Vulnerabilities

Do not disclose reusable credentials, private DNS data, private network details, personal query history, tokens, or other sensitive information in public issues.

For vulnerabilities that originate in inherited AdGuard Home code, the upstream AdGuard Home security reporting path remains relevant. Upstream currently directs vulnerability reports to `security@adguard.com` and asks reporters to identify the issue as an AdGuard Home vulnerability.

Before reporting or fixing an inherited issue, determine whether the GoreeCloud fork is affected and whether the vulnerability is still present in the exact GoreeCloud revision. Upstream security fixes should be evaluated promptly but must still pass GoreeCloud validation before release.

GoreeCloud-specific security reporting procedures will be documented separately before the project reaches a public production-ready release state.
