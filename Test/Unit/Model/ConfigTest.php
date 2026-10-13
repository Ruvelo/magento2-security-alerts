<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Model;

use Magento\Framework\App\Config\ScopeConfigInterface;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Model\Config;
use Ruvelo\SecurityAlerts\Model\Severity;

class ConfigTest extends TestCase
{
    /**
     * @param array<string, mixed> $values
     */
    private function config(array $values): Config
    {
        $scope = $this->createMock(ScopeConfigInterface::class);
        $scope->method('getValue')->willReturnCallback(static fn (string $path): mixed => $values[$path] ?? null);
        $scope->method('isSetFlag')->willReturnCallback(static fn (string $path): bool => (bool)($values[$path] ?? false));

        return new Config($scope);
    }

    public function testRecipientsAreSplitValidatedAndDeduplicated(): void
    {
        $config = $this->config([Config::XML_EMAILS => "ops@example.com, Dev@example.com;not-an-email\nops@EXAMPLE.com"]);

        $this->assertSame(['ops@example.com', 'Dev@example.com'], $config->recipients());
    }

    public function testNoRecipients(): void
    {
        $this->assertSame([], $this->config([])->recipients());
    }

    public function testMinimumSeverityFallsBackToMedium(): void
    {
        $this->assertSame(Severity::High, $this->config([Config::XML_MIN_SEVERITY => 'high'])->minimumSeverity());
        $this->assertSame(Severity::Medium, $this->config([Config::XML_MIN_SEVERITY => 'bogus'])->minimumSeverity());
    }

    public function testEnabledFlag(): void
    {
        $this->assertTrue($this->config([Config::XML_ENABLED => '1'])->isEnabled());
        $this->assertFalse($this->config([])->isEnabled());
    }

    public function testTheAdvisorySourceIsValtryUnlessTheOwnerOptsOut(): void
    {
        $this->assertSame('valtry', $this->config([])->advisorySource());
        $this->assertSame('valtry', $this->config([Config::XML_SOURCE => 'valtry'])->advisorySource());
        $this->assertSame('valtry', $this->config([Config::XML_SOURCE => 'something else'])->advisorySource());
        $this->assertSame('public', $this->config([Config::XML_SOURCE => 'public'])->advisorySource());
    }

    public function testTheSourceOptionsAreTheTwoTheDisclosureDescribes(): void
    {
        $options = (new \Ruvelo\SecurityAlerts\Model\Config\Source\AdvisorySource())->toOptionArray();

        $this->assertSame(['valtry', 'public'], array_column($options, 'value'));
    }
}
