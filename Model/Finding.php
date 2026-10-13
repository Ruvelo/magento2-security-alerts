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
     * @param string|null $identity The key the row was first stored under, when it differs from the one derived from the advisory id
     * @param list<string> $aliases Other ids for the same vulnerability, as the sources named them
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
        public readonly ?string $firstSeenAt = null,
        public readonly ?string $identity = null,
        public readonly array $aliases = []
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
     * The key the shared core knows this finding by: ecosystem, package and the advisory id as named now.
     *
     * @return string
     */
    public function coreKey(): string
    {
        return 'composer:' . $this->package . ':' . $this->advisoryId;
    }

    /**
     * What the finding has been stored under since it was first seen. It stays put when a source
     * later names the same advisory differently, so nothing is mistaken for new.
     *
     * @return string
     */
    public function identityKey(): string
    {
        return $this->identity ?? $this->coreKey();
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
            $this->firstSeenAt,
            $this->identity,
            $this->aliases
        );
    }

    /**
     * The finding as it is stored: kept in the row with this id, under this identity.
     *
     * @param int|null $id
     * @param string $identity
     * @return self
     */
    public function stored(?int $id, string $identity): self
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
            $this->exploited,
            $id,
            $this->dismissed,
            $this->firstSeenAt,
            $identity,
            $this->aliases
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
