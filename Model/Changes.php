<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model;

class Changes
{
    /**
     * __construct.
     *
     * @param list<Finding> $new Findings seen for the first time
     * @param list<Finding> $becameExploited Findings that were known, and have since been added to the CISA list
     * @param int $resolved Findings that no longer apply
     */
    public function __construct(
        public readonly array $new,
        public readonly array $becameExploited,
        public readonly int $resolved
    ) {
    }
}
