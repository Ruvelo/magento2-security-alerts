# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- Email: the "Exploited — patch now" section was printed even when nothing was exploited. `{{depend}}` treats the integer `0` as set under PHP 8, so the template now switches on `has_exploited` and `has_other` (empty string when off). Found by installing the module in a real Mage-OS.

### Added

- CI `install` job: installs the module in Mage-OS 2.x and 1.0.x with MySQL and OpenSearch, and checks the schema whitelist, DI compilation, the table, the CLI against the live sources, the cron job, the email and the admin page.

## [1.0.0] - 2026-10-12

First release.

### Added

- Daily check (cron, `default` group) of the exact Magento version and every Composer package in `composer.lock` against Packagist's security advisories, matched locally with `composer/semver`. Core is checked under both `magento/product-community-edition` and `magento/community-edition`, and a flaw listed under both is shown once.
- CISA Known Exploited Vulnerabilities catalogue: findings whose CVE is listed are marked "Exploited — patch now" and sorted first.
- `bin/magento ruvelo:security-alerts:check` with `--json`, `--fail-on=exploited|any` (exit code 1) and `--dry-run`. Exit code 2 when a source cannot be reached.
- Declarative-schema table `ruvelo_security_alerts_finding`, so only new findings, and findings that became exploited, are notified.
- Admin page at System → Tools → Security alerts (a server-rendered table), with a "Check now" button (form key, ACL) and per-finding "Dismiss".
- One admin system message while exploited findings are open and not dismissed. Nothing is shown on a clean store.
- Configuration at Stores → Configuration → Advanced → Ruvelo Security Alerts: enable, notification emails, minimum severity to email.
- Transactional email template, exploited findings first.
- ACL resources `Ruvelo_SecurityAlerts::alerts` and `Ruvelo_SecurityAlerts::config`.
- `ruvelo_security_alerts_found` event, dispatched with the findings after each check.

[Unreleased]: https://github.com/Ruvelo/magento2-security-alerts/compare/v1.0.0...HEAD
