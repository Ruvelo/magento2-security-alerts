<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model;

class ScanResult
{
    /**
     * __construct.
     *
     * @param list<Finding> $findings Exploited first, then by severity
     * @param list<string> $warnings Things that did not work but did not stop the check
     * @param int $packagesChecked
     */
    public function __construct(
        public readonly array $findings,
        public readonly array $warnings,
        public readonly int $packagesChecked
    ) {
    }

    /**
     * Exploited.
     *
     * @return list<Finding>
     */
    public function exploited(): array
    {
        return array_values(array_filter($this->findings, static fn (Finding $f): bool => $f->exploited));
    }
}
