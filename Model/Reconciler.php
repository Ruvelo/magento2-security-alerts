<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model;

/**
 * Compares a fresh scan with what is stored, so that only what changed counts as news.
 */
class Reconciler
{
    /**
     * __construct.
     *
     * @param FindingStoreInterface $store
     */
    public function __construct(private readonly FindingStoreInterface $store)
    {
    }

    /**
     * Reconcile.
     *
     * @param list<Finding> $current
     * @return Changes
     */
    public function reconcile(array $current): Changes
    {
        $stored = [];
        foreach ($this->store->all() as $row) {
            $stored[$row->key()] = $row;
        }

        $new = [];
        $becameExploited = [];
        $seen = [];
        foreach ($current as $finding) {
            $seen[$finding->key()] = true;
            $known = $stored[$finding->key()] ?? null;
            if ($known === null) {
                $this->store->insert($finding);
                $new[] = $finding;
                continue;
            }
            // Once exploited, always exploited: the CISA list can be briefly unreachable, and a
            // missing answer must not quietly lower the alarm.
            $exploited = $finding->exploited || $known->exploited;
            $merged = $finding->withExploited($exploited);
            $flipped = $exploited && !$known->exploited;
            $this->store->update($merged, $flipped);
            if ($flipped) {
                $becameExploited[] = $merged;
            }
        }

        $resolved = 0;
        foreach ($stored as $key => $row) {
            if (!isset($seen[$key]) && $row->id !== null) {
                $this->store->delete($row->id);
                $resolved++;
            }
        }

        return new Changes($new, $becameExploited, $resolved);
    }
}
