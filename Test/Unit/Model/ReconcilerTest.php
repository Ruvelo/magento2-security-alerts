<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Model;

use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Model\Reconciler;
use Ruvelo\SecurityAlerts\Test\Unit\Fake\Findings;
use Ruvelo\SecurityAlerts\Test\Unit\Fake\InMemoryStore;

class ReconcilerTest extends TestCase
{
    private InMemoryStore $store;

    private Reconciler $reconciler;

    protected function setUp(): void
    {
        $this->store = new InMemoryStore();
        $this->reconciler = new Reconciler($this->store);
    }

    public function testFirstRunReportsEverythingAsNew(): void
    {
        $changes = $this->reconciler->reconcile([Findings::make(advisory: 'PKSA-1'), Findings::make(advisory: 'PKSA-2')]);

        $this->assertCount(2, $changes->new);
        $this->assertSame([], $changes->becameExploited);
        $this->assertCount(2, $this->store->all());
    }

    public function testSecondRunWithTheSameFindingsIsNotNews(): void
    {
        $findings = [Findings::make(advisory: 'PKSA-1')];
        $this->reconciler->reconcile($findings);

        $changes = $this->reconciler->reconcile($findings);

        $this->assertSame([], $changes->new);
        $this->assertSame([], $changes->becameExploited);
        $this->assertSame(0, $changes->resolved);
        $this->assertCount(1, $this->store->all());
    }

    public function testAFindingThatBecomesExploitedIsNewsAgain(): void
    {
        $this->reconciler->reconcile([Findings::make(advisory: 'PKSA-1')]);

        $changes = $this->reconciler->reconcile([Findings::make(advisory: 'PKSA-1', exploited: true)]);

        $this->assertSame([], $changes->new);
        $this->assertCount(1, $changes->becameExploited);
        $this->assertTrue($this->store->all()[0]->exploited);
    }

    public function testExploitedStaysExploitedWhenTheCatalogueIsUnavailable(): void
    {
        $this->reconciler->reconcile([Findings::make(advisory: 'PKSA-1', exploited: true)]);

        $changes = $this->reconciler->reconcile([Findings::make(advisory: 'PKSA-1', exploited: false)]);

        $this->assertSame([], $changes->becameExploited);
        $this->assertTrue($this->store->all()[0]->exploited);
    }

    public function testBecomingExploitedReopensADismissedFinding(): void
    {
        $this->reconciler->reconcile([Findings::make(advisory: 'PKSA-1')]);
        $this->store->dismiss(1);
        $this->assertTrue($this->store->all()[0]->dismissed);

        $this->reconciler->reconcile([Findings::make(advisory: 'PKSA-1', exploited: true)]);

        $this->assertFalse($this->store->all()[0]->dismissed);
    }

    public function testADismissalSurvivesAnotherRun(): void
    {
        $this->reconciler->reconcile([Findings::make(advisory: 'PKSA-1')]);
        $this->store->dismiss(1);

        $this->reconciler->reconcile([Findings::make(advisory: 'PKSA-1')]);

        $this->assertTrue($this->store->all()[0]->dismissed);
    }

    public function testFindingsThatNoLongerApplyAreRemoved(): void
    {
        $this->reconciler->reconcile([Findings::make(advisory: 'PKSA-1'), Findings::make(advisory: 'PKSA-2')]);

        $changes = $this->reconciler->reconcile([Findings::make(advisory: 'PKSA-2')]);

        $this->assertSame(1, $changes->resolved);
        $this->assertCount(1, $this->store->all());
        $this->assertSame('PKSA-2', $this->store->all()[0]->advisoryId);
    }

    public function testAFindingThatReturnsAfterBeingFixedIsNewAgain(): void
    {
        $this->reconciler->reconcile([Findings::make(advisory: 'PKSA-1')]);
        $this->reconciler->reconcile([]);

        $changes = $this->reconciler->reconcile([Findings::make(advisory: 'PKSA-1')]);

        $this->assertCount(1, $changes->new);
    }

    public function testTheInstalledVersionIsRefreshed(): void
    {
        $this->reconciler->reconcile([Findings::make(advisory: 'PKSA-1', installed: '1.2.0')]);

        $this->reconciler->reconcile([Findings::make(advisory: 'PKSA-1', installed: '1.3.0')]);

        $this->assertSame('1.3.0', $this->store->all()[0]->installedVersion);
    }
}
