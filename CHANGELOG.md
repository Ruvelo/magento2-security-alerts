# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-10-13

The module now runs on [`ruvelo/security-advisories`](https://github.com/Ruvelo/security-advisories) ^1.1, the core shared by Ruvelo's security alerts, instead of its own copy of the lockfile reading, Packagist and CISA clients, matching and reconciling. A change to how results are built now needs a core release or a Valtry deploy, not a release of this module.

**Upgrading:** nothing to do. `setup:upgrade` adds two nullable columns, and the first check recognises every finding 1.0 stored, whichever source answers, so nothing is emailed again. By default a check now asks Valtry's Advisory API (package names only, never versions; signed answers) and falls back to Packagist and CISA automatically. To never contact Valtry, set **Advisory source** to *Public feeds only*, or set `RUVELO_ADVISORIES_SOURCE=public` in the environment. Until the core is on Packagist, `composer config repositories.ruvelo-core vcs https://github.com/Ruvelo/security-advisories` before `composer update`.

It is a minor release: the CLI options and exit codes, the configuration paths, the ACL resources, the `ruvelo_security_alerts_found` event and its `Finding` / `ScanResult` members, and the table are all unchanged or only added to. The classes that did the reading, fetching and matching itself (`Model\ComposerLock`, `Model\AdvisoryMatcher`, `Model\Source\*`, `Model\Http\*`) are gone and `Model\Scanner` has new constructor arguments. None is documented or marked `@api`, and `Scanner::scan()` is unchanged, but code that replaced one of them through `di.xml` needs a look.

### Added

- Valtry's signed Advisory API as the default source, with automatic fallback to the public feeds when it is unreachable, slow, answers with an error or a bad signature, or reports its data as out of date. Only package names are sent, never versions.
- Configuration **Advisory source** (*Valtry (default)* or *Public feeds only*), described right where it is set. `RUVELO_ADVISORIES_SOURCE=public` in the environment also opts out and wins over the setting.
- The data source is shown: a `Data source:` line in the CLI summary, `source` in `--json` (`valtry`, `public` or `mixed`), and on the admin page after the last check. `ScanResult::$source`, `ScanResult::sourceLabel()`.
- Finding identity that survives a source naming an advisory differently: rows keep the key they were first stored under (new nullable columns `identity_key` and `aliases`, whitelist updated), and a stored finding is recognised by its CVE and aliases too, so it is neither new nor resolved. `Finding::$identity`, `Finding::$aliases` (constructor arguments added at the end).
- CI `install` job: installs the module in Mage-OS 2.x and 1.0.x with MySQL and OpenSearch, and checks the schema whitelist, DI compilation, the table, the CLI against the live sources, the public-only path, rows stored the 1.0 way, the cron job, the email and the admin page.

### Changed

- HTTP goes through the core's `CurlClient` (Magento's stack has no single PSR-18 client to rely on) with PSR-17 factories from `guzzlehttp/psr7`, which Magento ships; the cache is a file cache under `var/ruvelo_security_alerts/`. The module now requires `ruvelo/security-advisories` ^1.1, `guzzlehttp/psr7` and `ext-curl`, and suggests `ext-sodium` (to verify Valtry's answers). It no longer requires `composer/semver` directly.
- A "Fixed in" that an advisory can only express as "the last affected release" now reads `>2.10.1` instead of being empty.
- Wording that named Packagist alone (the admin page's note, the configuration help) no longer does.
- Every check looks fresh: nothing from an earlier look is shown as current.

### Fixed

- Email: the "Exploited — patch now" section was printed even when nothing was exploited. `{{depend}}` treats the integer `0` as set under PHP 8, so the template now switches on `has_exploited` and `has_other` (empty string when off). Found by installing the module in a real Mage-OS.

### Removed

- The module's own `composer.lock` reader, Packagist and CISA clients, version matching and HTTP fetcher (now in the core).

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

[Unreleased]: https://github.com/Ruvelo/magento2-security-alerts/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Ruvelo/magento2-security-alerts/compare/v1.0.0...v1.1.0
