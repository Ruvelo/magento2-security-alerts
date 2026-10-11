<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model;

/**
 * One advisory that applies to one installed package.
 */
class Finding
{
    /**
     * __construct.
     *
     * @param string $package Composer package name
     * @param string $installedVersion
     * @param string $advisoryId Packagist advisory id, e.g. PKSA-xxxx
     * @param string $title
     * @param string|null $link
     * @param string|null $cve
     * @param string|null $severity As reported by Packagist, often null
     * @param string|null $fixedIn First version that is not affected, when it can be worked out
     * @param bool $exploited Listed in the CISA Known Exploited Vulnerabilities catalogue
     * @param int|null $id Row id, once stored
     * @param bool $dismissed Dismissed in the admin
     * @param string|null $firstSeenAt
     */
    public function __construct(
        public readonly string $package,
        public readonly string $installedVersion,
        public readonly string $advisoryId,
        public readonly string $title,
        public readonly ?string $link,
        public readonly ?string $cve,
        public readonly ?string $severity,
        public readonly ?string $fixedIn,
        public readonly bool $exploited = false,
        public readonly ?int $id = null,
        public readonly bool $dismissed = false,
        public readonly ?string $firstSeenAt = null
    ) {
    }

    /**
     * Key.
     *
     * @return string
     */
    public function key(): string
    {
        return $this->package . '|' . $this->advisoryId;
    }

    /**
     * Severity level.
     *
     * @return Severity
     */
    public function severityLevel(): Severity
    {
        return Severity::fromAdvisory($this->severity);
    }

    /**
     * With exploited.
     *
     * @param bool $exploited
     * @return self
     */
    public function withExploited(bool $exploited): self
    {
        return new self(
            $this->package,
            $this->installedVersion,
            $this->advisoryId,
            $this->title,
            $this->link,
            $this->cve,
            $this->severity,
            $this->fixedIn,
            $exploited,
            $this->id,
            $this->dismissed,
            $this->firstSeenAt
        );
    }

    /**
     * To array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'package' => $this->package,
            'installed_version' => $this->installedVersion,
            'advisory_id' => $this->advisoryId,
            'title' => $this->title,
            'link' => $this->link,
            'cve' => $this->cve,
            'severity' => $this->severity,
            'severity_level' => $this->severityLevel()->value,
            'fixed_in' => $this->fixedIn,
            'exploited' => $this->exploited,
        ];
    }
}
