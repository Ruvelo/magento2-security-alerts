<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Model;

use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Model\Severity;

class SeverityTest extends TestCase
{
    public function testUnratedAdvisoriesCountAsHigh(): void
    {
        $this->assertSame(Severity::High, Severity::fromAdvisory(null));
        $this->assertSame(Severity::High, Severity::fromAdvisory('something-new'));
    }

    public function testKnownValuesAreCaseInsensitive(): void
    {
        $this->assertSame(Severity::Critical, Severity::fromAdvisory(' Critical '));
        $this->assertSame(Severity::Low, Severity::fromAdvisory('LOW'));
    }

    public function testRanksAreOrdered(): void
    {
        $ranks = array_map(static fn (Severity $s): int => $s->rank(), Severity::cases());
        $sorted = $ranks;
        sort($sorted);
        $this->assertSame($sorted, $ranks);
        $this->assertSame('Medium', Severity::Medium->label());
    }
}
