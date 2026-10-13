<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Fake;

use Ruvelo\SecurityAlerts\Model\Finding;
use Ruvelo\SecurityAlerts\Model\FindingStoreInterface;

/**
 * Behaves like the database table, in an array.
 */
class InMemoryStore implements FindingStoreInterface
{
    /** @var array<int, array{finding: Finding, notified: bool, notified_exploited: bool}> */
    public array $rows = [];

    private int $next = 1;

    public function all(): array
    {
        return array_values(array_map(static fn (array $r): Finding => $r['finding'], $this->rows));
    }

    public function insert(Finding $finding): void
    {
        $id = $this->next++;
        $this->rows[$id] = [
            'finding' => $this->with($finding, $id, false),
            'notified' => false,
            'notified_exploited' => false,
        ];
    }

    public function update(Finding $finding, bool $reopen): void
    {
        foreach ($this->rows as $id => $row) {
            if ($finding->id !== null ? $id === $finding->id : $row['finding']->key() === $finding->key()) {
                $dismissed = $reopen ? false : $row['finding']->dismissed;
                $this->rows[$id]['finding'] = $this->with($finding, $id, $dismissed);
            }
        }
    }

    public function delete(int $id): void
    {
        unset($this->rows[$id]);
    }

    public function dismiss(int $id): void
    {
        $f = $this->rows[$id]['finding'];
        $this->rows[$id]['finding'] = $this->with($f, $id, true);
    }

    public function pendingNotification(): array
    {
        $pending = [];
        foreach ($this->rows as $row) {
            $f = $row['finding'];
            if (!$f->dismissed && (!$row['notified'] || ($f->exploited && !$row['notified_exploited']))) {
                $pending[] = $f;
            }
        }

        return $pending;
    }

    public function markNotified(array $findings): void
    {
        foreach ($findings as $f) {
            if ($f->id !== null) {
                $this->rows[$f->id]['notified'] = true;
                $this->rows[$f->id]['notified_exploited'] = $f->exploited;
            }
        }
    }

    public function openExploitedIds(): array
    {
        $ids = [];
        foreach ($this->rows as $id => $row) {
            if ($row['finding']->exploited && !$row['finding']->dismissed) {
                $ids[] = $id;
            }
        }

        return $ids;
    }

    private function with(Finding $f, int $id, bool $dismissed): Finding
    {
        return new Finding(
            $f->package,
            $f->installedVersion,
            $f->advisoryId,
            $f->title,
            $f->link,
            $f->cve,
            $f->severity,
            $f->fixedIn,
            $f->exploited,
            $id,
            $dismissed,
            '2026-10-12 00:00:00',
            $f->identity,
            $f->aliases
        );
    }
}
