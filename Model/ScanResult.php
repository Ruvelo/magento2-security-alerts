<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model;

class ScanResult
{
    public const SOURCE_VALTRY = 'valtry';
    public const SOURCE_PUBLIC = 'public';
    public const SOURCE_MIXED = 'mixed';

    /**
     * __construct.
     *
     * @param list<Finding> $findings Exploited first, then by severity
     * @param list<string> $warnings Things that did not work but did not stop the check
     * @param int $packagesChecked
     * @param string $source Where the advisories came from: "valtry", "public" or "mixed"
     */
    public function __construct(
        public readonly array $findings,
        public readonly array $warnings,
        public readonly int $packagesChecked,
        public readonly string $source = self::SOURCE_PUBLIC
    ) {
    }

    /**
     * Where the advisories came from, in words.
     *
     * @return string
     */
    public function sourceLabel(): string
    {
        return self::label($this->source);
    }

    /**
     * Label.
     *
     * @param string|null $source
     * @return string
     */
    public static function label(?string $source): string
    {
        return match ($source) {
            self::SOURCE_VALTRY => 'Valtry Advisory API',
            self::SOURCE_MIXED => 'Valtry Advisory API and public feeds',
            self::SOURCE_PUBLIC => 'Public feeds (Packagist, CISA)',
            default => 'Not known yet',
        };
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
