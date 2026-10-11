<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Model\Http;

use Magento\Framework\HTTP\ClientInterface;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Exception\SourceException;
use Ruvelo\SecurityAlerts\Model\Http\CurlFetcher;

class CurlFetcherTest extends TestCase
{
    public function testGetReturnsTheBody(): void
    {
        $client = $this->createMock(ClientInterface::class);
        $client->expects($this->once())->method('get')->with('https://example.com/a');
        $client->method('getStatus')->willReturn(200);
        $client->method('getBody')->willReturn('{"ok":true}');

        $this->assertSame('{"ok":true}', (new CurlFetcher($client))->get('https://example.com/a'));
    }

    public function testPostSendsTheFormBody(): void
    {
        $client = $this->createMock(ClientInterface::class);
        $client->expects($this->once())->method('post')->with('https://example.com/a', 'packages[]=x');
        $client->method('getStatus')->willReturn(200);
        $client->method('getBody')->willReturn('{}');

        $this->assertSame('{}', (new CurlFetcher($client))->postForm('https://example.com/a', 'packages[]=x'));
    }

    public function testANon200IsAnError(): void
    {
        $client = $this->createMock(ClientInterface::class);
        $client->method('getStatus')->willReturn(503);

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('HTTP 503');
        (new CurlFetcher($client))->get('https://example.com/a');
    }

    public function testATransportFailureIsAnError(): void
    {
        $client = $this->createMock(ClientInterface::class);
        $client->method('get')->willThrowException(new \RuntimeException('timeout'));

        $this->expectException(SourceException::class);
        (new CurlFetcher($client))->get('https://example.com/a');
    }
}
