<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model;

use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\App\ProductMetadataInterface;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Finding as CoreFinding;
use Ruvelo\SecurityAdvisories\Report;
use Ruvelo\SecurityAdvisories\Severity as CoreSeverity;
use Ruvelo\SecurityAlerts\Exception\SourceException;
use Ruvelo\SecurityAlerts\Model\Packages\MagentoPackages;

/**
 * Works out which known vulnerabilities apply to this store right now. Reads, never writes.
 *
 * The reading of composer.lock, the advisory sources (Valtry first, the public feeds as the
 * fallback), the matching and the exploited-in-the-wild verdict belong to the shared core,
 * ruvelo/security-advisories. What is Magento's stays here: the core version, the bundled
 * modules that are skipped, and the two edition names a core flaw is filed under.
 */
class Scanner
{
    /** The two names Packagist files Magento core advisories under. */
    public const CORE_PACKAGES = MagentoPackages::CORE_PACKAGES;

    /**
     * __construct.
     *
     * @param ProductMetadataInterface $productMetadata
     * @param DirectoryList $directoryList
     * @param CoreFactory $coreFactory
     * @param Config $config
     */
    public function __construct(
        private readonly ProductMetadataInterface $productMetadata,
        private readonly DirectoryList $directoryList,
        private readonly CoreFactory $coreFactory,
        private readonly Config $config
    ) {
    }

    /**
     * Scan.
     *
     * @return ScanResult
     * @throws SourceException When no advisory source can be reached: without it there is no answer to give
     */
    public function scan(): ScanResult
    {
        $packages = new MagentoPackages($this->directoryList->getRoot() . '/composer.lock', $this->coreVersion());
        if (!$packages->hasAnything()) {
            throw new SourceException('There is nothing to check: no Magento version and no composer.lock.');
        }

        // A check is always a fresh look: nothing old is shown as current.
        $report = $this->coreFactory->create($packages, $this->config->advisorySource())->scan(true);

        $warnings = $packages->warnings();
        if (!$report->isCheckedFor(Ecosystem::Composer)) {
            throw new SourceException(implode(' ', $report->problems) ?: 'No advisory source could be reached.');
        }
        // What is left (the exploited list, say) did not stop the check, but is worth a line.
        foreach ($report->problems as $problem) {
            $warnings[] = $problem;
        }

        if ($report->packageCount() === 0) {
            throw new SourceException('There is nothing to check: no Magento version and no readable composer.lock.');
        }

        $kept = $this->dedupeCore($report->findings);
        $findings = $this->sort(array_map(fn (CoreFinding $f): Finding => $this->toFinding($f), $kept));

        return new ScanResult($findings, $warnings, $report->packageCount(), $this->origin($report));
    }

    /**
     * To finding.
     *
     * @param CoreFinding $core
     * @return Finding
     */
    private function toFinding(CoreFinding $core): Finding
    {
        return new Finding(
            $core->package,
            $core->installed,
            $core->advisoryId,
            $core->title,
            $core->link,
            $core->cve,
            $core->severity === CoreSeverity::NotRated ? null : $core->severity->value,
            $core->fixedIn,
            $core->isExploited(),
            null,
            false,
            null,
            null,
            $core->aliases
        );
    }

    /**
     * Origin.
     *
     * @param Report $report
     * @return string
     */
    private function origin(Report $report): string
    {
        return match ($report->source) {
            ScanResult::SOURCE_VALTRY => ScanResult::SOURCE_VALTRY,
            ScanResult::SOURCE_MIXED => ScanResult::SOURCE_MIXED,
            default => ScanResult::SOURCE_PUBLIC,
        };
    }

    /**
     * Packagist lists the same Magento core flaw under both edition names. Show it once.
     *
     * @param list<CoreFinding> $findings
     * @return list<CoreFinding>
     */
    private function dedupeCore(array $findings): array
    {
        // Same order every run, so the surviving row (and its key in the store) never flips.
        $rank = static fn (CoreFinding $f): int => (int)array_search($f->package, self::CORE_PACKAGES, true);
        usort($findings, static fn (CoreFinding $a, CoreFinding $b): int => $rank($a) <=> $rank($b));

        $seen = [];
        $result = [];
        foreach ($findings as $finding) {
            if (in_array($finding->package, self::CORE_PACKAGES, true) && $finding->cve !== null) {
                $coreKey = 'core|' . $finding->cve;
                if (isset($seen[$coreKey])) {
                    continue;
                }
                $seen[$coreKey] = true;
            }
            $result[] = $finding;
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
}
