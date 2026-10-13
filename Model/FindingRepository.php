<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model;

use Magento\Framework\App\ResourceConnection;
use Magento\Framework\DB\Adapter\AdapterInterface;

class FindingRepository implements FindingStoreInterface
{
    public const TABLE = 'ruvelo_security_alerts_finding';

    /**
     * __construct.
     *
     * @param ResourceConnection $resource
     */
    public function __construct(private readonly ResourceConnection $resource)
    {
    }

    /**
     * @inheritdoc
     */
    public function all(): array
    {
        return $this->fetch($this->select());
    }

    /**
     * @inheritdoc
     */
    public function insert(Finding $finding): void
    {
        $now = gmdate('Y-m-d H:i:s');
        $this->connection()->insert($this->table(), $this->columns($finding) + [
            'first_seen_at' => $now,
            'last_seen_at' => $now,
        ]);
    }

    /**
     * @inheritdoc
     */
    public function update(Finding $finding, bool $reopen): void
    {
        $data = $this->columns($finding) + ['last_seen_at' => gmdate('Y-m-d H:i:s')];
        if ($reopen) {
            $data['dismissed_at'] = null;
        }
        // A row is found by its id; the advisory id is what a source calls it now, and may change.
        $where = $finding->id !== null
            ? ['finding_id = ?' => $finding->id]
            : ['package_name = ?' => $finding->package, 'advisory_id = ?' => $finding->advisoryId];
        $this->connection()->update($this->table(), $data, $where);
    }

    /**
     * @inheritdoc
     */
    public function delete(int $id): void
    {
        $this->connection()->delete($this->table(), ['finding_id = ?' => $id]);
    }

    /**
     * @inheritdoc
     */
    public function dismiss(int $id): void
    {
        $this->connection()->update(
            $this->table(),
            ['dismissed_at' => gmdate('Y-m-d H:i:s')],
            ['finding_id = ?' => $id]
        );
    }

    /**
     * @inheritdoc
     */
    public function pendingNotification(): array
    {
        $select = $this->select()
            ->where('dismissed_at IS NULL')
            ->where('(notified_at IS NULL OR (exploited = 1 AND notified_exploited = 0))');

        return $this->fetch($select);
    }

    /**
     * @inheritdoc
     */
    public function markNotified(array $findings): void
    {
        $now = gmdate('Y-m-d H:i:s');
        foreach ($findings as $finding) {
            if ($finding->id === null) {
                continue;
            }
            $this->connection()->update(
                $this->table(),
                ['notified_at' => $now, 'notified_exploited' => $finding->exploited ? 1 : 0],
                ['finding_id = ?' => $finding->id]
            );
        }
    }

    /**
     * @inheritdoc
     */
    public function openExploitedIds(): array
    {
        $select = $this->connection()->select()
            ->from($this->table(), ['finding_id'])
            ->where('exploited = 1')
            ->where('dismissed_at IS NULL')
            ->order('finding_id ASC');

        return array_map('intval', $this->connection()->fetchCol($select));
    }

    /**
     * Select.
     *
     * @return \Magento\Framework\DB\Select
     */
    private function select(): \Magento\Framework\DB\Select
    {
        return $this->connection()->select()
            ->from($this->table())
            ->order(['exploited DESC', 'package_name ASC', 'advisory_id ASC']);
    }

    /**
     * Fetch.
     *
     * @param \Magento\Framework\DB\Select $select
     * @return list<Finding>
     */
    private function fetch(\Magento\Framework\DB\Select $select): array
    {
        $findings = [];
        foreach ($this->connection()->fetchAll($select) as $row) {
            $findings[] = new Finding(
                (string)$row['package_name'],
                (string)$row['installed_version'],
                (string)$row['advisory_id'],
                (string)$row['title'],
                $row['link'] !== null ? (string)$row['link'] : null,
                $row['cve'] !== null ? (string)$row['cve'] : null,
                $row['severity'] !== null ? (string)$row['severity'] : null,
                $row['fixed_in'] !== null ? (string)$row['fixed_in'] : null,
                (int)$row['exploited'] === 1,
                (int)$row['finding_id'],
                $row['dismissed_at'] !== null,
                (string)$row['first_seen_at'],
                ($row['identity_key'] ?? null) !== null && $row['identity_key'] !== '' ? (string)$row['identity_key'] : null,
                $this->decodeAliases($row['aliases'] ?? null)
            );
        }
        usort(
            $findings,
            static fn (Finding $a, Finding $b): int => ($b->exploited <=> $a->exploited)
                ?: ($b->severityLevel()->rank() <=> $a->severityLevel()->rank())
                ?: ($a->package <=> $b->package)
                ?: ($a->advisoryId <=> $b->advisoryId)
        );

        return $findings;
    }

    /**
     * Columns.
     *
     * @param Finding $finding
     * @return array<string, mixed>
     */
    private function columns(Finding $finding): array
    {
        return [
            'package_name' => $finding->package,
            'installed_version' => $finding->installedVersion,
            'advisory_id' => $finding->advisoryId,
            'title' => mb_substr($finding->title, 0, 500),
            'link' => $finding->link !== null ? mb_substr($finding->link, 0, 500) : null,
            'cve' => $finding->cve,
            'severity' => $finding->severity,
            'fixed_in' => $finding->fixedIn,
            'exploited' => $finding->exploited ? 1 : 0,
            'identity_key' => $finding->identityKey(),
            'aliases' => $finding->aliases === [] ? null : (string)json_encode(array_values($finding->aliases)),
        ];
    }

    /**
     * Decode aliases.
     *
     * @param mixed $json
     * @return list<string>
     */
    private function decodeAliases(mixed $json): array
    {
        $aliases = is_string($json) && $json !== '' ? json_decode($json, true) : null;

        return is_array($aliases) ? array_values(array_filter($aliases, 'is_string')) : [];
    }

    /**
     * Connection.
     *
     * @return AdapterInterface
     */
    private function connection(): AdapterInterface
    {
        return $this->resource->getConnection();
    }

    /**
     * Table.
     *
     * @return string
     */
    private function table(): string
    {
        return $this->resource->getTableName(self::TABLE);
    }
}
