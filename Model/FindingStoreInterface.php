<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model;

/**
 * The findings seen so far. A finding exists while it applies; when the package is updated it is deleted.
 */
interface FindingStoreInterface
{
    /**
     * All.
     *
     * @return list<Finding> Exploited first, then by severity
     */
    public function all(): array;

    /**
     * Insert.
     *
     * @param Finding $finding
     * @return void
     */
    public function insert(Finding $finding): void;

    /**
     * Refreshes what the row says about a finding already stored.
     *
     * @param Finding $finding
     * @param bool $reopen Clear the dismissal, because the finding has become exploited
     * @return void
     */
    public function update(Finding $finding, bool $reopen): void;

    /**
     * Delete.
     *
     * @param int $id
     * @return void
     */
    public function delete(int $id): void;

    /**
     * Dismiss.
     *
     * @param int $id
     * @return void
     */
    public function dismiss(int $id): void;

    /**
     * Findings nobody has been told about yet: new ones, and ones that have become exploited since.
     * Dismissed findings are left out.
     *
     * @return list<Finding>
     */
    public function pendingNotification(): array;

    /**
     * Mark notified.
     *
     * @param list<Finding> $findings
     * @return void
     */
    public function markNotified(array $findings): void;

    /**
     * Exploited findings that nobody has dismissed.
     *
     * @return list<int> Ids
     */
    public function openExploitedIds(): array;
}
