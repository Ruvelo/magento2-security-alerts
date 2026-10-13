<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Model;

use Magento\Framework\App\ResourceConnection;
use Magento\Framework\DB\Adapter\AdapterInterface;
use Magento\Framework\DB\Select;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Model\FindingRepository;
use Ruvelo\SecurityAlerts\Test\Unit\Fake\Findings;

/**
 * Checks what is written to the table. The SQL itself needs a database, see the README.
 */
class FindingRepositoryTest extends TestCase
{
    /** @var AdapterInterface&MockObject */
    private AdapterInterface $connection;

    private FindingRepository $repository;

    protected function setUp(): void
    {
        $this->connection = $this->createMock(AdapterInterface::class);
        $resource = $this->createMock(ResourceConnection::class);
        $resource->method('getConnection')->willReturn($this->connection);
        $resource->method('getTableName')->willReturnCallback(static fn (string $t): string => 'pre_' . $t);
        $this->repository = new FindingRepository($resource);
    }

    public function testInsertWritesTheColumnsAndTimestamps(): void
    {
        $this->connection->expects($this->once())->method('insert')->with(
            'pre_ruvelo_security_alerts_finding',
            $this->callback(static function (array $data): bool {
                return $data['package_name'] === 'acme/module-widgets'
                    && $data['advisory_id'] === 'PKSA-1'
                    && $data['exploited'] === 1
                    && $data['fixed_in'] === '9.9.9'
                    && isset($data['first_seen_at'], $data['last_seen_at']);
            })
        );

        $this->repository->insert(Findings::make(exploited: true));
    }

    public function testUpdateOnlyClearsTheDismissalWhenReopening(): void
    {
        $seen = [];
        $this->connection->method('update')->willReturnCallback(
            static function (string $table, array $data, array $where) use (&$seen): int {
                $seen[] = [$data, $where];

                return 1;
            }
        );

        $this->repository->update(Findings::make(), false);
        $this->repository->update(Findings::make(exploited: true), true);

        $this->assertArrayNotHasKey('dismissed_at', $seen[0][0]);
        $this->assertArrayHasKey('dismissed_at', $seen[1][0]);
        $this->assertNull($seen[1][0]['dismissed_at']);
        $this->assertSame(
            ['package_name = ?' => 'acme/module-widgets', 'advisory_id = ?' => 'PKSA-1'],
            $seen[0][1]
        );
    }

    public function testDismissAndDeleteTargetOneRow(): void
    {
        $this->connection->expects($this->once())->method('delete')
            ->with('pre_ruvelo_security_alerts_finding', ['finding_id = ?' => 7]);
        $this->connection->expects($this->once())->method('update')->with(
            'pre_ruvelo_security_alerts_finding',
            $this->callback(static fn (array $d): bool => isset($d['dismissed_at'])),
            ['finding_id = ?' => 3]
        );

        $this->repository->delete(7);
        $this->repository->dismiss(3);
    }

    public function testRowsBecomeFindingsExploitedFirst(): void
    {
        $select = $this->createMock(Select::class);
        $select->method('from')->willReturnSelf();
        $select->method('order')->willReturnSelf();
        $this->connection->method('select')->willReturn($select);
        $row = static fn (int $id, string $pkg, int $exploited, ?string $dismissed): array => [
            'finding_id' => $id, 'package_name' => $pkg, 'installed_version' => '1.0', 'advisory_id' => 'PKSA-' . $id,
            'title' => 'T', 'link' => null, 'cve' => null, 'severity' => null, 'fixed_in' => null,
            'exploited' => $exploited, 'first_seen_at' => '2026-10-12 03:17:00', 'dismissed_at' => $dismissed,
        ];
        $this->connection->method('fetchAll')->willReturn([
            $row(1, 'a/a', 0, null),
            $row(2, 'b/b', 1, '2026-10-12 04:00:00'),
        ]);

        $findings = $this->repository->all();

        $this->assertSame([2, 1], array_map(static fn ($f): ?int => $f->id, $findings));
        $this->assertTrue($findings[0]->exploited);
        $this->assertTrue($findings[0]->dismissed);
        $this->assertFalse($findings[1]->dismissed);
        $this->assertNull($findings[1]->severity);
    }

    public function testMarkNotifiedRecordsTheExploitedState(): void
    {
        $writes = [];
        $this->connection->method('update')->willReturnCallback(
            static function (string $table, array $data, array $where) use (&$writes): int {
                $writes[$where['finding_id = ?']] = $data['notified_exploited'];

                return 1;
            }
        );
        $stored = fn (int $id, bool $exploited) => new \Ruvelo\SecurityAlerts\Model\Finding(
            'a/a',
            '1',
            'P' . $id,
            't',
            null,
            null,
            null,
            null,
            $exploited,
            $id
        );

        $this->repository->markNotified([$stored(1, true), $stored(2, false), Findings::make()]);

        $this->assertSame([1 => 1, 2 => 0], $writes);
    }

    public function testAStoredRowIsUpdatedByIdWhenASourceNamesItDifferently(): void
    {
        $seen = [];
        $this->connection->method('update')->willReturnCallback(
            static function (string $table, array $data, array $where) use (&$seen): int {
                $seen = [$data, $where];

                return 1;
            }
        );

        $this->repository->update(Findings::make(advisory: 'GHSA-new', aliases: ['PKSA-old'])->stored(5, 'composer:acme/module-widgets:PKSA-old'), false);

        $this->assertSame(['finding_id = ?' => 5], $seen[1]);
        $this->assertSame('GHSA-new', $seen[0]['advisory_id']);
        $this->assertSame('composer:acme/module-widgets:PKSA-old', $seen[0]['identity_key']);
        $this->assertSame('["PKSA-old"]', $seen[0]['aliases']);
    }

    public function testTheIdentityAndAliasesComeBackFromTheRow(): void
    {
        $select = $this->createMock(Select::class);
        $select->method('from')->willReturnSelf();
        $select->method('order')->willReturnSelf();
        $this->connection->method('select')->willReturn($select);
        $base = [
            'installed_version' => '1.0', 'title' => 'T', 'link' => null, 'cve' => 'CVE-2099-0001', 'severity' => null,
            'fixed_in' => null, 'exploited' => 0, 'first_seen_at' => '2026-10-12 03:17:00', 'dismissed_at' => null,
        ];
        $this->connection->method('fetchAll')->willReturn([
            $base + ['finding_id' => 1, 'package_name' => 'a/a', 'advisory_id' => 'PKSA-1', 'identity_key' => null, 'aliases' => null],
            $base + ['finding_id' => 2, 'package_name' => 'b/b', 'advisory_id' => 'PKSA-2', 'identity_key' => 'composer:b/b:OLD', 'aliases' => '["GHSA-x","bad",1]'],
        ]);

        [$legacy, $migrated] = $this->repository->all();

        $this->assertNull($legacy->identity);
        $this->assertSame('composer:a/a:PKSA-1', $legacy->identityKey(), 'A row stored before 1.1 is known by its package and advisory id');
        $this->assertSame([], $legacy->aliases);
        $this->assertSame('composer:b/b:OLD', $migrated->identityKey());
        $this->assertSame(['GHSA-x', 'bad'], $migrated->aliases);
    }
}
