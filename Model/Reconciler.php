<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model;

use DateTimeImmutable;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Finding as CoreFinding;
use Ruvelo\SecurityAdvisories\KevEntry;
use Ruvelo\SecurityAdvisories\Reconciler as CoreReconciler;
use Ruvelo\SecurityAdvisories\Report;
use Ruvelo\SecurityAdvisories\Severity as CoreSeverity;

/**
 * Compares a fresh scan with what is stored, so that only what changed counts as news.
 *
 * What counts as the same finding is decided by the shared core, which also recognises a
 * stored row by its CVE and aliases. A row keeps the identity it was first stored under, so a
 * source that names an advisory differently is not mistaken for a new one.
 */
class Reconciler
{
    private CoreReconciler $core;

    /**
     * __construct.
     *
     * @param FindingStoreInterface $store
     */
    public function __construct(private readonly FindingStoreInterface $store)
    {
        $this->core = new CoreReconciler();
    }

    /**
     * Reconcile.
     *
     * @param list<Finding> $current
     * @return Changes
     */
    public function reconcile(array $current): Changes
    {
        $rows = [];
        $known = [];
        $lastSeen = [];
        foreach ($this->store->all() as $row) {
            $key = $row->identityKey();
            $rows[$key] = $row;
            $known[$key] = $row->exploited;
            $lastSeen[$key] = $this->toCore($row)->toArray();
        }

        $report = new Report(
            array_map(fn (Finding $finding): CoreFinding => $this->toCore($finding), $current),
            ['composer' => count($current)],
            [Ecosystem::Composer]
        );
        $now = [];
        foreach ($current as $finding) {
            $now[$finding->coreKey()] = $finding;
        }

        $changes = $this->core->reconcile($known, $report, $lastSeen);
        $next = $this->core->next($known, $report, [], $lastSeen);
        $seen = $this->core->lastSeen($lastSeen, $report, $next);

        // What is no longer in the next known set was resolved, or folded into another row for the
        // same vulnerability. Deleting first frees the unique (package, advisory) pair for a renamed row.
        foreach ($rows as $key => $row) {
            if ($row->id !== null && !array_key_exists($key, $next)) {
                $this->store->delete($row->id);
            }
        }

        $new = [];
        $becameExploited = [];
        foreach (array_keys($next) as $key) {
            $finding = $now[$seen[$key]['key'] ?? ''] ?? null;
            if ($finding === null) {
                continue; // not vouched for this time: left as it was
            }
            $row = $rows[$key] ?? null;
            if ($row === null) {
                $this->store->insert($finding->stored(null, $key));
                $new[] = $finding;
                continue;
            }
            // Once exploited, always exploited: the CISA list can be briefly unreachable, and a
            // missing answer must not quietly lower the alarm.
            $exploited = $finding->exploited || $row->exploited;
            $merged = $finding->withExploited($exploited)->stored($row->id, $key);
            $flipped = $exploited && !$row->exploited;
            $this->store->update($merged, $flipped);
            if ($flipped) {
                $becameExploited[] = $merged;
            }
        }

        return new Changes($new, $becameExploited, count($changes->resolved));
    }

    /**
     * The core's view of a finding.
     *
     * @param Finding $finding
     * @return CoreFinding
     */
    private function toCore(Finding $finding): CoreFinding
    {
        return new CoreFinding(
            Ecosystem::Composer,
            $finding->package,
            $finding->installedVersion,
            $finding->advisoryId,
            $finding->title,
            CoreSeverity::parse($finding->severity),
            $finding->link,
            $finding->cve,
            $finding->fixedIn,
            null,
            null,
            $finding->exploited
                ? new KevEntry($finding->cve ?? $finding->advisoryId, $finding->title, new DateTimeImmutable('@0'))
                : null,
            false,
            $finding->aliases
        );
    }
}
