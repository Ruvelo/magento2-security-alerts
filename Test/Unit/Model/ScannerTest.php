<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Model;

use Magento\Framework\App\ProductMetadataInterface;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Exception\SourceException;
use Ruvelo\SecurityAlerts\Model\AdvisoryMatcher;
use Ruvelo\SecurityAlerts\Model\ComposerLock;
use Ruvelo\SecurityAlerts\Model\Finding;
use Ruvelo\SecurityAlerts\Model\Scanner;
use Ruvelo\SecurityAlerts\Model\Source\AdvisoryClient;
use Ruvelo\SecurityAlerts\Model\Source\KevCatalogue;
use Ruvelo\SecurityAlerts\Test\Unit\Fake\FakeFetcher;

class ScannerTest extends TestCase
{
    private FakeFetcher $fetcher;

    protected function setUp(): void
    {
        $this->fetcher = new FakeFetcher();
    }

    /**
     * @param array<string, string>|SourceException $lock
     */
    private function scanner(string $magentoVersion, array|SourceException $lock = []): Scanner
    {
        $metadata = $this->createMock(ProductMetadataInterface::class);
        $metadata->method('getVersion')->willReturn($magentoVersion);
        $composerLock = $this->createMock(ComposerLock::class);
        if ($lock instanceof SourceException) {
            $composerLock->method('packages')->willThrowException($lock);
        } else {
            $composerLock->method('packages')->willReturn($lock);
        }

        return new Scanner(
            $metadata,
            $composerLock,
            new AdvisoryClient($this->fetcher),
            new KevCatalogue($this->fetcher),
            new AdvisoryMatcher()
        );
    }

    /**
     * @param list<Finding> $findings
     * @return list<string>
     */
    private function cves(array $findings): array
    {
        return array_map(static fn (Finding $f): string => (string)$f->cve, $findings);
    }

    public function testFlagsAnExploitedCoreFlawFirst(): void
    {
        $result = $this->scanner('2.4.7', ['acme/module-widgets' => '1.2.0'])->scan();

        $first = $result->findings[0];
        $this->assertSame('CVE-2024-34102', $first->cve);
        $this->assertTrue($first->exploited);
        $this->assertSame('2.4.7', $first->installedVersion);
        $this->assertSame('2.4.7-p1', $first->fixedIn);
        $this->assertCount(1, $result->exploited());
        $this->assertContains('CVE-2099-0001', $this->cves($result->findings));
        $this->assertSame([], $result->warnings);
    }

    public function testAPatchedStoreIsClean(): void
    {
        $result = $this->scanner('2.4.8-p5')->scan();

        $this->assertNotContains('CVE-2024-34102', $this->cves($result->findings));
        $this->assertSame([], $result->exploited());
    }

    public function testChecksBothCoreEditionNamesButReportsAFlawOnce(): void
    {
        $result = $this->scanner('2.4.7')->scan();

        $this->assertSame(2, $result->packagesChecked);
        $matches = array_filter($result->findings, static fn (Finding $f): bool => $f->cve === 'CVE-2024-34102');
        $this->assertCount(1, $matches);
        $this->assertSame('magento/product-community-edition', array_values($matches)[0]->package);
        // community-edition has its own advisories too.
        $this->assertContains('CVE-2025-54264', $this->cves($result->findings));
    }

    public function testThirdPartyPackageIsMatchedByItsInstalledVersion(): void
    {
        $affected = $this->scanner('2.4.8-p5', ['acme/module-widgets' => '1.2.0'])->scan();
        $fixed = $this->scanner('2.4.8-p5', ['acme/module-widgets' => '1.4.2'])->scan();

        $this->assertSame(['CVE-2099-0001'], $this->cves($affected->findings));
        $this->assertSame('1.4.2', $affected->findings[0]->fixedIn);
        $this->assertSame('high', $affected->findings[0]->severity);
        $this->assertSame([], $fixed->findings);
    }

    public function testPackagesNotInstalledAreIgnored(): void
    {
        $result = $this->scanner('2.4.8-p5', ['other/thing' => '1.0.0'])->scan();

        $this->assertNotContains('CVE-2099-0001', $this->cves($result->findings));
    }

    public function testExploitedComesBeforeSeverity(): void
    {
        $result = $this->scanner('2.4.7', ['acme/module-widgets' => '1.2.0'])->scan();

        $exploited = array_map(static fn (Finding $f): bool => $f->exploited, $result->findings);
        $sorted = $exploited;
        rsort($sorted);
        $this->assertSame($sorted, $exploited);
    }

    public function testASilentCisaOutageWarnsAndFlagsNothing(): void
    {
        $this->fetcher->kevDown = true;

        $result = $this->scanner('2.4.7')->scan();

        $this->assertNotEmpty($result->findings);
        $this->assertSame([], $result->exploited());
        $this->assertCount(1, $result->warnings);
        $this->assertStringContainsString('CISA', $result->warnings[0]);
    }

    public function testPackagistOutageIsAnError(): void
    {
        $this->fetcher->packagistDown = true;

        $this->expectException(SourceException::class);
        $this->scanner('2.4.7')->scan();
    }

    public function testMissingLockfileStillChecksTheCore(): void
    {
        $result = $this->scanner('2.4.7', new SourceException('composer.lock was not found'))->scan();

        $this->assertContains('CVE-2024-34102', $this->cves($result->findings));
        $this->assertSame(['composer.lock was not found'], $result->warnings);
    }

    public function testUnreadableMagentoVersionStillChecksExtensions(): void
    {
        $result = $this->scanner('UNKNOWN', ['acme/module-widgets' => '1.2.0'])->scan();

        $this->assertSame(['CVE-2099-0001'], $this->cves($result->findings));
        $this->assertStringContainsString('Magento version', $result->warnings[0]);
    }

    public function testNothingToCheckIsAnError(): void
    {
        $this->expectException(SourceException::class);
        $this->scanner('UNKNOWN', new SourceException('no lock'))->scan();
    }
}
