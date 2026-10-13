<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Model;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Exception\SourceException;
use Ruvelo\SecurityAlerts\Model\Finding;
use Ruvelo\SecurityAlerts\Model\ScanResult;
use Ruvelo\SecurityAlerts\Test\Unit\Fake\FakeHttp;
use Ruvelo\SecurityAlerts\Test\Unit\Fake\ScannerFactory;

class ScannerTest extends TestCase
{
    private FakeHttp $http;

    protected function setUp(): void
    {
        $this->http = new FakeHttp();
        putenv('RUVELO_ADVISORIES_SOURCE');
    }

    protected function tearDown(): void
    {
        putenv('RUVELO_ADVISORIES_SOURCE');
    }

    /**
     * @return array<string, array{string}>
     */
    public static function sources(): array
    {
        return ['through Valtry' => ['valtry'], 'through the public feeds' => ['public']];
    }

    /**
     * @param array<string, string>|null $lock
     */
    private function scan(string $magentoVersion, ?array $lock = [], string $source = 'valtry'): ScanResult
    {
        return ScannerFactory::build($this, $this->http, ScannerFactory::root($lock), $magentoVersion, $source)->scan();
    }

    /**
     * @param list<Finding> $findings
     * @return list<string>
     */
    private function cves(array $findings): array
    {
        return array_map(static fn (Finding $f): string => (string)$f->cve, $findings);
    }

    #[DataProvider('sources')]
    public function testFlagsAnExploitedCoreFlawFirst(string $source): void
    {
        $result = $this->scan('2.4.7', ['acme/module-widgets' => '1.2.0'], $source);

        $first = $result->findings[0];
        $this->assertSame('CVE-2024-34102', $first->cve);
        $this->assertTrue($first->exploited);
        $this->assertSame('2.4.7', $first->installedVersion);
        $this->assertSame('2.4.7-p1', $first->fixedIn);
        $this->assertCount(1, $result->exploited());
        $this->assertContains('CVE-2099-0001', $this->cves($result->findings));
        $this->assertSame([], $result->warnings);
        $this->assertSame($source, $result->source);
    }

    #[DataProvider('sources')]
    public function testAPatchedStoreIsClean(string $source): void
    {
        $result = $this->scan('2.4.8-p5', [], $source);

        $this->assertNotContains('CVE-2024-34102', $this->cves($result->findings));
        $this->assertSame([], $result->exploited());
    }

    #[DataProvider('sources')]
    public function testChecksBothCoreEditionNamesButReportsAFlawOnce(string $source): void
    {
        $result = $this->scan('2.4.7', [], $source);

        $this->assertSame(2, $result->packagesChecked);
        $matches = array_filter($result->findings, static fn (Finding $f): bool => $f->cve === 'CVE-2024-34102');
        $this->assertCount(1, $matches);
        $this->assertSame('magento/product-community-edition', array_values($matches)[0]->package);
        // community-edition has its own advisories too.
        $this->assertContains('CVE-2025-54264', $this->cves($result->findings));
    }

    #[DataProvider('sources')]
    public function testThirdPartyPackageIsMatchedByItsInstalledVersion(string $source): void
    {
        $affected = $this->scan('2.4.8-p5', ['acme/module-widgets' => '1.2.0'], $source);
        $fixed = $this->scan('2.4.8-p5', ['acme/module-widgets' => '1.4.2'], $source);

        $this->assertSame(['CVE-2099-0001'], $this->cves($affected->findings));
        $this->assertSame('1.4.2', $affected->findings[0]->fixedIn);
        $this->assertSame('high', $affected->findings[0]->severity);
        $this->assertSame([], $fixed->findings);
    }

    public function testPackagesNotInstalledAreIgnored(): void
    {
        $result = $this->scan('2.4.8-p5', ['other/thing' => '1.0.0']);

        $this->assertNotContains('CVE-2099-0001', $this->cves($result->findings));
    }

    #[DataProvider('sources')]
    public function testExploitedComesBeforeSeverity(string $source): void
    {
        $result = $this->scan('2.4.7', ['acme/module-widgets' => '1.2.0'], $source);

        $exploited = array_map(static fn (Finding $f): bool => $f->exploited, $result->findings);
        $sorted = $exploited;
        rsort($sorted);
        $this->assertSame($sorted, $exploited);
    }

    public function testBundledMagentoModulesAreNeverLookedUp(): void
    {
        $this->scan('2.4.8-p5', [
            'magento/module-catalog' => '104.0.8',
            'mage-os/theme-frontend-luma' => '1.0.0',
            'magento/product-community-edition' => '2.4.8-p5',
            'acme/module-widgets' => '1.2.0',
        ]);

        $sent = implode("\n", $this->http->requestsTo('valtry'));
        $this->assertStringContainsString('acme/module-widgets', $sent);
        $this->assertStringContainsString('magento/product-community-edition', $sent);
        $this->assertStringNotContainsString('module-catalog', $sent);
        $this->assertStringNotContainsString('theme-frontend-luma', $sent);
    }

    public function testValtryIsToldPackageNamesAndNeverVersions(): void
    {
        $this->scan('2.4.7', ['acme/module-widgets' => '1.2.0']);

        $sent = implode("\n", $this->http->requestsTo('valtry'));
        $this->assertNotSame('', $sent);
        $this->assertStringNotContainsString('2.4.7', $sent);
        $this->assertStringNotContainsString('1.2.0', $sent);
        $this->assertSame([], $this->http->requestsTo('packagist.org'));
        $this->assertSame([], $this->http->requestsTo('cisa.gov'), 'Valtry already says what is exploited');
    }

    public function testThePublicFeedsOnlyHearPackageNames(): void
    {
        $this->scan('2.4.7', ['acme/module-widgets' => '1.2.0'], 'public');

        $sent = implode("\n", $this->http->requestsTo('packagist.org'));
        $this->assertStringContainsString('acme%2Fmodule-widgets', $sent);
        $this->assertStringNotContainsString('2.4.7', $sent);
        $this->assertStringNotContainsString('1.2.0', $sent);
        $this->assertSame([], $this->http->requestsTo('valtry'));
    }

    public function testTheOptOutNeverContactsValtry(): void
    {
        $result = $this->scan('2.4.7', [], 'public');

        $this->assertSame('public', $result->source);
        $this->assertSame([], $this->http->requestsTo('valtry'));
    }

    public function testTheEnvironmentOptsOutWhateverTheConfigSays(): void
    {
        putenv('RUVELO_ADVISORIES_SOURCE=public');

        $result = $this->scan('2.4.7', [], 'valtry');

        $this->assertSame('public', $result->source);
        $this->assertSame([], $this->http->requestsTo('valtry'));
    }

    public function testFallsBackToThePublicFeedsWhenValtryIsDown(): void
    {
        $this->http->valtryDown = true;

        $result = $this->scan('2.4.7', ['acme/module-widgets' => '1.2.0']);

        $this->assertSame('public', $result->source);
        $this->assertSame('CVE-2024-34102', $result->findings[0]->cve);
        $this->assertTrue($result->findings[0]->exploited);
        $this->assertSame([], $result->warnings);
    }

    public function testFallsBackWhenValtrysAnswerIsNotSignedByAPinnedKey(): void
    {
        $this->http->tamper = static fn (string $body, string $header): array => [
            str_replace('Arbitrary Code', 'Harmless', $body),
            $header,
        ];

        $result = $this->scan('2.4.7');

        $this->assertSame('public', $result->source);
        $this->assertStringContainsString('Arbitrary Code', $result->findings[0]->title);
    }

    public function testASilentCisaOutageWarnsAndFlagsNothing(): void
    {
        $this->http->kevDown = true;

        $result = $this->scan('2.4.7', [], 'public');

        $this->assertNotEmpty($result->findings);
        $this->assertSame([], $result->exploited());
        $this->assertCount(1, $result->warnings);
        $this->assertStringContainsString('exploited', $result->warnings[0]);
    }

    public function testPackagistOutageIsAnError(): void
    {
        $this->http->packagistDown = true;

        $this->expectException(SourceException::class);
        $this->scan('2.4.7', [], 'public');
    }

    public function testBothValtryAndPackagistDownIsAnError(): void
    {
        $this->http->valtryDown = true;
        $this->http->packagistDown = true;

        $this->expectException(SourceException::class);
        $this->scan('2.4.7');
    }

    public function testMissingLockfileStillChecksTheCore(): void
    {
        $result = $this->scan('2.4.7', null);

        $this->assertContains('CVE-2024-34102', $this->cves($result->findings));
        $this->assertCount(1, $result->warnings);
        $this->assertStringContainsString('composer.lock was not found', $result->warnings[0]);
    }

    public function testAnUnreadableLockfileStillChecksTheCore(): void
    {
        $root = ScannerFactory::root(null, '{ nope');

        $result = ScannerFactory::build($this, $this->http, $root, '2.4.7')->scan();

        $this->assertContains('CVE-2024-34102', $this->cves($result->findings));
        $this->assertCount(1, $result->warnings);
        $this->assertStringContainsString('composer.lock', $result->warnings[0]);
    }

    public function testUnreadableMagentoVersionStillChecksExtensions(): void
    {
        $result = $this->scan('UNKNOWN', ['acme/module-widgets' => '1.2.0']);

        $this->assertSame(['CVE-2099-0001'], $this->cves($result->findings));
        $this->assertStringContainsString('Magento version', $result->warnings[0]);
    }

    public function testNothingToCheckIsAnError(): void
    {
        $this->expectException(SourceException::class);
        $this->scan('UNKNOWN', null);
    }

    public function testTheSourceHasAWordingThatNamesNoJudgement(): void
    {
        $this->assertSame('Valtry Advisory API', (new ScanResult([], [], 0, 'valtry'))->sourceLabel());
        $this->assertSame('Public feeds (Packagist, CISA)', (new ScanResult([], [], 0, 'public'))->sourceLabel());
        $this->assertSame('Valtry Advisory API and public feeds', (new ScanResult([], [], 0, 'mixed'))->sourceLabel());
    }
}
