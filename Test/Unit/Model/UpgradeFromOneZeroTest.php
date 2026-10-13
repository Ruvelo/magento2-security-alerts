<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Model;

use Magento\Framework\Event\ManagerInterface;
use Magento\Framework\FlagManager;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Model\CheckOutcome;
use Ruvelo\SecurityAlerts\Model\Checker;
use Ruvelo\SecurityAlerts\Model\Finding;
use Ruvelo\SecurityAlerts\Model\Notifier;
use Ruvelo\SecurityAlerts\Model\Reconciler;
use Ruvelo\SecurityAlerts\Test\Unit\Fake\FakeHttp;
use Ruvelo\SecurityAlerts\Test\Unit\Fake\InMemoryStore;
use Ruvelo\SecurityAlerts\Test\Unit\Fake\ScannerFactory;

/**
 * A store that ran 1.0 has a table full of findings it already emailed about, stored the way 1.0
 * stored them: no identity key, no aliases, one row per package and advisory id. The first check
 * after upgrading must recognise every one of them, whichever source answers, and tell nobody again.
 */
class UpgradeFromOneZeroTest extends TestCase
{
    private const LOCK = ['acme/module-widgets' => '1.2.0'];

    private FakeHttp $http;

    private InMemoryStore $store;

    /** @var list<array<string, mixed>> The event payloads dispatched */
    private array $events = [];

    protected function setUp(): void
    {
        putenv('RUVELO_ADVISORIES_SOURCE');
        $this->http = new FakeHttp();
        $this->store = new InMemoryStore();
        $this->events = [];
    }

    protected function tearDown(): void
    {
        putenv('RUVELO_ADVISORIES_SOURCE');
    }

    /**
     * The table as 1.0 left it after its daily checks: what the public path finds today, all of
     * it emailed, in the shape 1.0 stored.
     *
     * @return int How many rows
     */
    private function seedOneZeroRows(): int
    {
        $result = ScannerFactory::build($this, new FakeHttp(), ScannerFactory::root(self::LOCK), '2.4.7', 'public')->scan();
        foreach ($result->findings as $f) {
            $this->store->insert(new Finding(
                $f->package,
                $f->installedVersion,
                $f->advisoryId,
                $f->title,
                $f->link,
                $f->cve,
                $f->severity,
                $f->fixedIn,
                $f->exploited
            ));
        }
        $this->store->markNotified($this->store->all());
        $this->assertGreaterThanOrEqual(5, count($this->store->all()));
        $this->assertNotEmpty($this->store->openExploitedIds());

        return count($this->store->all());
    }

    private function check(string $source): CheckOutcome
    {
        $events = $this->createMock(ManagerInterface::class);
        $events->method('dispatch')->willReturnCallback(function (string $name, array $data): void {
            $this->events[] = $data;
        });
        $notifier = $this->createMock(Notifier::class);
        $notifier->method('notifyPending')->willReturnCallback(fn (): int => count($this->store->pendingNotification()));

        return (new Checker(
            ScannerFactory::build($this, $this->http, ScannerFactory::root(self::LOCK), '2.4.7', $source),
            new Reconciler($this->store),
            $notifier,
            $events,
            $this->createMock(FlagManager::class)
        ))->run();
    }

    /**
     * @return array<string, array{string}>
     */
    public static function sources(): array
    {
        return ['the Valtry path' => ['valtry'], 'the public path' => ['public']];
    }

    #[DataProvider('sources')]
    public function testTheFirstCheckAfterUpgradingSendsNothingNew(string $source): void
    {
        $rows = $this->seedOneZeroRows();
        $before = array_map(static fn (Finding $f): string => $f->package . '|' . $f->advisoryId, $this->store->all());

        $outcome = $this->check($source);

        $this->assertSame($source, $outcome->result->source);
        $this->assertCount($rows, $outcome->result->findings);
        $this->assertSame([], $outcome->changes->new);
        $this->assertSame([], $outcome->changes->becameExploited);
        $this->assertSame(0, $outcome->changes->resolved);
        $this->assertSame(0, $outcome->emailed);
        $this->assertSame([], $this->store->pendingNotification());
        $this->assertCount($rows, $this->store->all());
        $this->assertSame($before, array_map(static fn (Finding $f): string => $f->package . '|' . $f->advisoryId, $this->store->all()));
        $this->assertCount(1, $this->events, 'Observers still hear what applies');
        $this->assertSame([], $this->events[0]['new_findings']);
    }

    #[DataProvider('sources')]
    public function testTheCheckAfterThatIsQuietToo(string $source): void
    {
        $this->seedOneZeroRows();
        $this->check($source);

        $outcome = $this->check($source);

        $this->assertSame([], $outcome->changes->new);
        $this->assertSame(0, $outcome->emailed);
        $this->assertSame([], $this->store->pendingNotification());
    }

    public function testSwitchingPathsAfterUpgradingIsQuietToo(): void
    {
        $this->seedOneZeroRows();
        $this->check('valtry');

        $outcome = $this->check('public');

        $this->assertSame([], $outcome->changes->new);
        $this->assertSame(0, $outcome->emailed);
    }

    #[DataProvider('sources')]
    public function testARowStoredUnderAnotherAdvisoryIdIsRecognisedByItsCve(string $source): void
    {
        $this->seedOneZeroRows();
        // 1.0 knew this flaw under an id the answer no longer uses.
        $old = null;
        foreach ($this->store->rows as $id => $row) {
            if ($row['finding']->cve === 'CVE-2024-34102') {
                $f = $row['finding'];
                $old = $f->advisoryId;
                $this->store->rows[$id]['finding'] = new Finding(
                    $f->package,
                    $f->installedVersion,
                    'OLD-ID',
                    $f->title,
                    $f->link,
                    $f->cve,
                    $f->severity,
                    $f->fixedIn,
                    $f->exploited,
                    $id,
                    false,
                    '2026-10-12 00:00:00'
                );
            }
        }
        $this->assertNotNull($old);

        $outcome = $this->check($source);

        $this->assertSame([], $outcome->changes->new);
        $this->assertSame([], $outcome->changes->becameExploited);
        $this->assertSame(0, $outcome->changes->resolved);
        $this->assertSame([], $this->store->pendingNotification());
        $renamed = array_values(array_filter($this->store->all(), static fn (Finding $f): bool => $f->cve === 'CVE-2024-34102'));
        $this->assertCount(1, $renamed);
        $this->assertSame($old, $renamed[0]->advisoryId, 'The row shows the advisory as the answer names it now');
        $this->assertSame('composer:magento/product-community-edition:OLD-ID', $renamed[0]->identityKey(), 'and keeps the identity it had');
    }

    #[DataProvider('sources')]
    public function testADismissalSurvivesTheUpgrade(string $source): void
    {
        $this->seedOneZeroRows();
        $id = $this->store->all()[0]->id;
        $this->assertNotNull($id);
        $this->store->dismiss($id);

        $this->check($source);

        $this->assertTrue($this->store->all()[0]->dismissed);
        $this->assertSame([], $this->store->pendingNotification());
    }

    #[DataProvider('sources')]
    public function testAFindingThatWasFixedIsStillResolvedQuietly(string $source): void
    {
        $this->seedOneZeroRows();
        $this->store->insert(new Finding('acme/removed', '1.0.0', 'PKSA-gone', 'Fixed long ago', null, null, 'high', null));
        $this->store->markNotified($this->store->all());
        $rows = count($this->store->all());

        $outcome = $this->check($source);

        $this->assertSame(1, $outcome->changes->resolved);
        $this->assertSame([], $outcome->changes->new);
        $this->assertCount($rows - 1, $this->store->all());
        $this->assertSame([], $this->store->pendingNotification());
    }

    #[DataProvider('sources')]
    public function testAnUnnotifiedRowIsStillNotifiedAfterTheUpgrade(string $source): void
    {
        $this->seedOneZeroRows();
        // The email never went out for this one (the mail server was down).
        $this->store->rows[1]['notified'] = false;

        $outcome = $this->check($source);

        $this->assertSame([], $outcome->changes->new);
        $this->assertSame(1, $outcome->emailed);
        $this->assertCount(1, $this->store->pendingNotification());
    }
}
