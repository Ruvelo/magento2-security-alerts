# Contributing to Security Alerts for Magento 2

Thanks for helping! Bug reports, false positives, docs fixes and features are all welcome.

## Before you start

- **A wrong or missing finding:** [open an issue](https://github.com/Ruvelo/magento2-security-alerts/issues/new/choose) with the package, the installed version and the advisory id. Matching rules come from the shared core ([ruvelo/security-advisories](https://github.com/Ruvelo/security-advisories)) and the advisory data from Packagist, so a wrong match belongs in the core, and an advisory that is wrong at the source should be fixed in [FriendsOfPHP/security-advisories](https://github.com/FriendsOfPHP/security-advisories) too.
- **Features:** open an issue first if it's more than a small change, so we can agree on the shape before you spend time on it.
- **Security issues:** don't open an issue. See [SECURITY.md](https://github.com/Ruvelo/.github/blob/main/SECURITY.md).

## Setup

You need PHP 8.2+ and Composer. You do not need a Magento install or a database: the Magento classes come from the public [Mage-OS Composer mirror](https://repo.mage-os.org/) as dev dependencies, and the tests mock everything else.

The module requires `ruvelo/security-advisories`, which is not on Packagist yet, so point Composer at GitHub first (this is not committed into `composer.json`; CI does the same):

```bash
git clone https://github.com/<you>/magento2-security-alerts && cd magento2-security-alerts
composer config repositories.core vcs https://github.com/Ruvelo/security-advisories
composer install
composer check
```

`composer check` runs exactly what CI runs:

| Command | What it does |
|---|---|
| `composer test` | PHPUnit 10 unit tests |
| `composer lint` | `php -l` on every PHP file |
| `composer cs` | Magento coding standard (PHPCS), errors only |
| `composer analyse` | PHPStan level 8 with `bitexpert/phpstan-magento` |

The `install` job in CI is the only thing that runs the module inside Magento (Mage-OS, MySQL, OpenSearch). Its helper scripts are in `.github/ci/`. It does use the network, for the real Packagist and CISA answers.

Unit tests never touch the network. Packagist, CISA and Valtry answers come from `Test/Unit/Fake/FakeHttp.php`, built on the fixtures in `Test/Unit/_files/` (trimmed copies of real responses); Valtry's are signed with a key made for the test.

## Making a change

1. Branch from `main`.
2. Write a test that fails without your change.
3. Keep the public surface stable: the CLI options and exit codes, config paths, ACL ids, the event name and its data, and the table.
4. Run `composer check`.
5. Add a line under **Unreleased** in [CHANGELOG.md](CHANGELOG.md).
6. Open the pull request.

## Where things live

```
Model/Scanner.php            Magento's part: version + composer.lock => findings, core editions deduped
Model/CoreFactory.php        Wires the shared core: HTTP, cache, Valtry first and the public feeds as fallback
Model/Packages/              What is installed: composer.lock without the bundled modules, plus the core
Model/Reconciler.php         What is new, what became exploited, what is resolved (the core decides, rows keep their identity)
Model/Notifier.php           The email
Model/System/                The one admin system message
Console/, Cron/, Controller/ The ways to run a check, and the admin page's actions
etc/, view/                  Magento XML, the template, the email template
Test/Unit/                   Unit tests; ModuleWiringTest cross-checks the XML
art/                         README previews: HTML mocks and the script that renders them
```

## Style

- `declare(strict_types=1)` everywhere, typed properties and return types.
- No `@phpstan-ignore` or baseline entries: fix the cause.
- Comments explain *why*, not *what*.
- Nothing in the admin, emails or CLI links anywhere but advisory pages.

By contributing you agree that your work is released under the [MIT license](LICENSE) and that you'll follow the [code of conduct](https://github.com/Ruvelo/.github/blob/main/CODE_OF_CONDUCT.md).
