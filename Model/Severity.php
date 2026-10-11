<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model;

enum Severity: string
{
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
    case Critical = 'critical';

    /**
     * Packagist leaves most Magento advisories unrated. Those are Adobe bulletins,
     * which are rarely minor, so an unrated advisory counts as high.
     *
     * @param string|null $value
     * @return self
     */
    public static function fromAdvisory(?string $value): self
    {
        return $value === null ? self::High : (self::tryFrom(strtolower(trim($value))) ?? self::High);
    }

    /**
     * Rank.
     *
     * @return int
     */
    public function rank(): int
    {
        return match ($this) {
            self::Low => 1,
            self::Medium => 2,
            self::High => 3,
            self::Critical => 4,
        };
    }

    /**
     * Label.
     *
     * @return string
     */
    public function label(): string
    {
        return ucfirst($this->value);
    }
}
