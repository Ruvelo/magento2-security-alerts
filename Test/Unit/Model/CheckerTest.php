<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Model;

use Magento\Framework\Event\ManagerInterface;
use Magento\Framework\FlagManager;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Exception\SourceException;
use Ruvelo\SecurityAlerts\Model\Changes;
use Ruvelo\SecurityAlerts\Model\Checker;
use Ruvelo\SecurityAlerts\Model\Notifier;
use Ruvelo\SecurityAlerts\Model\Reconciler;
use Ruvelo\SecurityAlerts\Model\ScanResult;
use Ruvelo\SecurityAlerts\Model\Scanner;
use Ruvelo\SecurityAlerts\Test\Unit\Fake\Findings;
use Ruvelo\SecurityAlerts\Test\Unit\Fake\InMemoryStore;

class CheckerTest extends TestCase
{
    public function testStoresDispatchesTheEventNotifiesAndRemembersWhenItRan(): void
    {
        $finding = Findings::make(exploited: true);
        $other = Findings::make(advisory: 'PKSA-2');
        $scanner = $this->createMock(Scanner::class);
        $scanner->method('scan')->willReturn(new ScanResult([$finding, $other], [], 10));
        $notifier = $this->createMock(Notifier::class);
        $notifier->expects($this->once())->method('notifyPending')->willReturn(2);
        $flags = $this->createMock(FlagManager::class);
        $flags->expects($this->exactly(2))->method('saveFlag')->willReturnCallback(
            function (string $flag, mixed $value): void {
                $this->assertContains($flag, [Checker::FLAG_LAST_CHECK, Checker::FLAG_LAST_SOURCE]);
                $this->assertIsString($value);
            }
        );
        $events = $this->createMock(ManagerInterface::class);
        $events->expects($this->once())->method('dispatch')->with(
            'ruvelo_security_alerts_found',
            $this->callback(static fn (array $data): bool => $data['findings'] === [$finding, $other]
                && count($data['new_findings']) === 2
                && $data['result'] instanceof ScanResult)
        );
        $store = new InMemoryStore();

        $outcome = (new Checker($scanner, new Reconciler($store), $notifier, $events, $flags))->run();

        $this->assertCount(2, $store->all());
        $this->assertCount(2, $outcome->changes->new);
        $this->assertSame(2, $outcome->emailed);
    }

    public function testNoEventWhenTheStoreIsClean(): void
    {
        $scanner = $this->createMock(Scanner::class);
        $scanner->method('scan')->willReturn(new ScanResult([], [], 10));
        $events = $this->createMock(ManagerInterface::class);
        $events->expects($this->never())->method('dispatch');
        $notifier = $this->createMock(Notifier::class);
        $notifier->method('notifyPending')->willReturn(0);

        $outcome = (new Checker(
            $scanner,
            new Reconciler(new InMemoryStore()),
            $notifier,
            $events,
            $this->createMock(FlagManager::class)
        ))->run();

        $this->assertInstanceOf(Changes::class, $outcome->changes);
        $this->assertSame(0, $outcome->emailed);
    }

    public function testAFailedScanChangesNothing(): void
    {
        $scanner = $this->createMock(Scanner::class);
        $scanner->method('scan')->willThrowException(new SourceException('Packagist is down.'));
        $store = new InMemoryStore();
        $store->insert(Findings::make());
        $flags = $this->createMock(FlagManager::class);
        $flags->expects($this->never())->method('saveFlag');

        try {
            (new Checker(
                $scanner,
                new Reconciler($store),
                $this->createMock(Notifier::class),
                $this->createMock(ManagerInterface::class),
                $flags
            ))->run();
            $this->fail('Expected a SourceException.');
        } catch (SourceException) {
            $this->assertCount(1, $store->all());
        }
    }
}
