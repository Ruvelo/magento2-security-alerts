<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model;

use Magento\Framework\App\ProductMetadataInterface;
use Ruvelo\SecurityAlerts\Exception\SourceException;
use Ruvelo\SecurityAlerts\Model\Source\AdvisoryClient;
use Ruvelo\SecurityAlerts\Model\Source\KevCatalogue;

/**
 * Works out which known vulnerabilities apply to this store right now. Reads, never writes.
 */
class Scanner
{
    /** The two names Packagist files Magento core advisories under. */
    public const CORE_PACKAGES = ['magento/product-community-edition', 'magento/community-edition'];

    /**
     * __construct.
     *
     * @param ProductMetadataInterface $productMetadata
     * @param ComposerLock $composerLock
     * @param AdvisoryClient $advisories
     * @param KevCatalogue $kev
     * @param AdvisoryMatcher $matcher
     */
    public function __construct(
        private readonly ProductMetadataInterface $productMetadata,
        private readonly ComposerLock $composerLock,
        private readonly AdvisoryClient $advisories,
        private readonly KevCatalogue $kev,
        private readonly AdvisoryMatcher $matcher
    ) {
    }

    /**
     * Scan.
     *
     * @return ScanResult
     * @throws SourceException When Packagist cannot be reached: without it there is no answer to give
     */
    public function scan(): ScanResult
    {
        $warnings = [];
        $installed = [];

        try {
            $installed = $this->composerLock->packages();
        } catch (SourceException $e) {
            $warnings[] = $e->getMessage();
        }

        $core = $this->coreVersion();
        if ($core === null) {
            $warnings[] = 'The Magento version could not be read, so core advisories were not checked.';
        } else {
            foreach (self::CORE_PACKAGES as $name) {
                $installed[$name] = $core;
            }
        }
        if ($installed === []) {
            throw new SourceException('There is nothing to check: no Magento version and no composer.lock.');
        }

        $advisories = $this->advisories->fetch(array_keys($installed));

        try {
            $exploitedCves = $this->kev->exploitedCves();
        } catch (SourceException $e) {
            $exploitedCves = [];
            $warnings[] = 'The CISA exploited-vulnerabilities list could not be fetched, so nothing is flagged as exploited this time: '
                . $e->getMessage();
        }

        $findings = [];
        foreach ($advisories as $package => $list) {
            if (!isset($installed[$package])) {
                continue;
            }
            foreach ($list as $advisory) {
                $finding = $this->toFinding($package, $installed[$package], $advisory, $exploitedCves);
                if ($finding !== null) {
                    $findings[$finding->key()] = $finding;
                }
            }
        }

        return new ScanResult($this->sort(array_values($this->dedupeCore($findings))), $warnings, count($installed));
    }

    /**
     * To finding.
     *
     * @param string $package
     * @param string $version
     * @param array<string, mixed> $advisory
     * @param array<string, true> $exploitedCves
     * @return Finding|null
     */
    private function toFinding(string $package, string $version, array $advisory, array $exploitedCves): ?Finding
    {
        $constraint = $advisory['affectedVersions'] ?? null;
        $id = $advisory['advisoryId'] ?? null;
        if (!is_string($constraint) || !is_string($id) || !$this->matcher->affects($version, $constraint)) {
            return null;
        }
        $cve = $this->text($advisory['cve'] ?? null);

        return new Finding(
            $package,
            $version,
            $id,
            $this->text($advisory['title'] ?? null) ?? $id,
            $this->text($advisory['link'] ?? null),
            $cve,
            $this->text($advisory['severity'] ?? null),
            $this->matcher->fixedIn($version, $constraint),
            $cve !== null && isset($exploitedCves[strtoupper($cve)])
        );
    }

    /**
     * Packagist lists the same Magento core flaw under both edition names. Show it once.
     *
     * @param array<string, Finding> $findings
     * @return array<string, Finding>
     */
    private function dedupeCore(array $findings): array
    {
        // Same order every run, so the surviving row (and its key in the store) never flips.
        $rank = static fn (Finding $f): int => (int)array_search($f->package, self::CORE_PACKAGES, true);
        uasort($findings, static fn (Finding $a, Finding $b): int => $rank($a) <=> $rank($b));

        $seen = [];
        $result = [];
        foreach ($findings as $key => $finding) {
            if (in_array($finding->package, self::CORE_PACKAGES, true) && $finding->cve !== null) {
                $coreKey = 'core|' . $finding->cve;
                if (isset($seen[$coreKey])) {
                    continue;
                }
                $seen[$coreKey] = true;
            }
            $result[$key] = $finding;
        }

        return $result;
    }

    /**
     * Sort.
     *
     * @param list<Finding> $findings
     * @return list<Finding>
     */
    private function sort(array $findings): array
    {
        usort(
            $findings,
            static fn (Finding $a, Finding $b): int => ($b->exploited <=> $a->exploited)
                ?: ($b->severityLevel()->rank() <=> $a->severityLevel()->rank())
                ?: ($a->package <=> $b->package)
                ?: ($a->advisoryId <=> $b->advisoryId)
        );

        return $findings;
    }

    /**
     * Core version.
     *
     * @return string|null
     */
    private function coreVersion(): ?string
    {
        $version = trim($this->productMetadata->getVersion());
        if ($version === '' || preg_match('/^\d+\.\d+/', $version) !== 1) {
            return null;
        }

        return $version;
    }

    /**
     * Text.
     *
     * @param mixed $value
     * @return string|null
     */
    private function text(mixed $value): ?string
    {
        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }
}
