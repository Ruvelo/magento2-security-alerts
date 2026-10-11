<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Model\Source;

use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Exception\SourceException;
use Ruvelo\SecurityAlerts\Model\Http\FetcherInterface;
use Ruvelo\SecurityAlerts\Model\Source\KevCatalogue;
use Ruvelo\SecurityAlerts\Test\Unit\Fake\FakeFetcher;

class KevCatalogueTest extends TestCase
{
    public function testReadsTheCveIds(): void
    {
        $fetcher = new FakeFetcher();
        $cves = (new KevCatalogue($fetcher))->exploitedCves();

        $this->assertSame(['GET ' . KevCatalogue::URL], $fetcher->requests);
        $this->assertArrayHasKey('CVE-2024-34102', $cves);
        $this->assertArrayHasKey('CVE-2025-54236', $cves);
        $this->assertArrayNotHasKey('CVE-2099-0001', $cves);
    }

    public function testRejectsAnythingElse(): void
    {
        $fetcher = $this->createMock(FetcherInterface::class);
        $fetcher->method('get')->willReturn('{"vulnerabilities": "none"}');

        $this->expectException(SourceException::class);
        (new KevCatalogue($fetcher))->exploitedCves();
    }
}
