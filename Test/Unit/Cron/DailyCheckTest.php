<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Cron;

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Ruvelo\SecurityAlerts\Cron\DailyCheck;
use Ruvelo\SecurityAlerts\Exception\SourceException;
use Ruvelo\SecurityAlerts\Model\Checker;
use Ruvelo\SecurityAlerts\Model\Config;

class DailyCheckTest extends TestCase
{
    private function config(bool $enabled): Config
    {
        $config = $this->createMock(Config::class);
        $config->method('isEnabled')->willReturn($enabled);

        return $config;
    }

    public function testDoesNothingWhenDisabled(): void
    {
        $checker = $this->createMock(Checker::class);
        $checker->expects($this->never())->method('run');

        (new DailyCheck($this->config(false), $checker, $this->createMock(LoggerInterface::class)))->execute();
    }

    public function testRunsWhenEnabled(): void
    {
        $checker = $this->createMock(Checker::class);
        $checker->expects($this->once())->method('run');

        (new DailyCheck($this->config(true), $checker, $this->createMock(LoggerInterface::class)))->execute();
    }

    public function testASourceOutageIsLoggedNotThrown(): void
    {
        $checker = $this->createMock(Checker::class);
        $checker->method('run')->willThrowException(new SourceException('Packagist is down.'));
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())->method('warning')->with($this->stringContains('Packagist is down.'));

        (new DailyCheck($this->config(true), $checker, $logger))->execute();
    }
}
