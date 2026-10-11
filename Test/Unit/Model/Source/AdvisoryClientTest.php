<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Model\Source;

use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Exception\SourceException;
use Ruvelo\SecurityAlerts\Model\Http\FetcherInterface;
use Ruvelo\SecurityAlerts\Model\Source\AdvisoryClient;
use Ruvelo\SecurityAlerts\Test\Unit\Fake\FakeFetcher;

class AdvisoryClientTest extends TestCase
{
    public function testAsksForPackageNamesOnly(): void
    {
        $fetcher = new FakeFetcher();
        $result = (new AdvisoryClient($fetcher))->fetch(['magento/product-community-edition', 'acme/module-widgets']);

        $this->assertCount(1, $fetcher->requests);
        $this->assertSame(
            'POST https://packagist.org/api/security-advisories/ '
            . 'packages[]=magento%2Fproduct-community-edition&packages[]=acme%2Fmodule-widgets',
            $fetcher->requests[0]
        );
        $this->assertCount(6, $result['magento/product-community-edition']);
        $this->assertSame('CVE-2099-0001', $result['acme/module-widgets'][0]['cve']);
    }

    public function testSplitsLongListsAndDeduplicates(): void
    {
        $fetcher = new FakeFetcher();
        $names = array_map(static fn (int $i): string => 'vendor/package-' . $i, range(1, 150));
        $names[] = 'vendor/package-1';

        (new AdvisoryClient($fetcher))->fetch($names);

        $this->assertCount(2, $fetcher->requests);
        $this->assertSame(100, substr_count($fetcher->requests[0], 'packages[]='));
        $this->assertSame(50, substr_count($fetcher->requests[1], 'packages[]='));
    }

    public function testAnUnexpectedAnswerIsAnError(): void
    {
        $fetcher = $this->createMock(FetcherInterface::class);
        $fetcher->method('postForm')->willReturn('<html>Maintenance</html>');

        $this->expectException(SourceException::class);
        (new AdvisoryClient($fetcher))->fetch(['a/b']);
    }
}
