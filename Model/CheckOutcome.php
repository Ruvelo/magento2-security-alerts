<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model;

class CheckOutcome
{
    /**
     * __construct.
     *
     * @param ScanResult $result
     * @param Changes $changes
     * @param int $emailed Findings put in an email
     */
    public function __construct(
        public readonly ScanResult $result,
        public readonly Changes $changes,
        public readonly int $emailed
    ) {
    }
}
