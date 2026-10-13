<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Fake;

use Ruvelo\SecurityAlerts\Model\Finding;

class Findings
{
    /**
     * Make.
     *
     * @param list<string> $aliases
     */
    public static function make(
        string $package = 'acme/module-widgets',
        string $advisory = 'PKSA-1',
        bool $exploited = false,
        ?string $severity = 'high',
        string $installed = '1.2.0',
        string $title = 'A flaw',
        ?string $cve = null,
        array $aliases = []
    ): Finding {
        return new Finding(
            $package,
            $installed,
            $advisory,
            $title,
            'https://example.com/' . $advisory,
            $cve ?? 'CVE-2099-' . substr($advisory, -4),
            $severity,
            '9.9.9',
            $exploited,
            null,
            false,
            null,
            null,
            $aliases
        );
    }
}
