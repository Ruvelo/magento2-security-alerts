<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model;

use Composer\Semver\Comparator;
use Composer\Semver\Semver;
use Throwable;

/**
 * Decides whether an advisory's affected-version constraint covers an installed version,
 * and works out which version fixes it.
 */
class AdvisoryMatcher
{
    private const MAX_HOPS = 10;

    /**
     * Affects.
     *
     * @param string $installedVersion
     * @param string $constraint e.g. "<2.4.4|>=2.4.4,<2.4.4-p9|>=2.4.5,<2.4.5-p8"
     * @return bool False when the version or constraint cannot be understood (a dev branch, say)
     */
    public function affects(string $installedVersion, string $constraint): bool
    {
        try {
            return Semver::satisfies($installedVersion, $constraint);
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * The nearest version above the installed one that no branch of the constraint covers.
     *
     * Magento advisories list patch lines, so "<2.4.4" alone is not a fix: 2.4.4 is still
     * affected until 2.4.4-p9. This walks up the upper bounds until it lands outside the constraint.
     *
     * @param string $installedVersion
     * @param string $constraint
     * @return string|null Null when the constraint has no upper bound that could be followed
     */
    public function fixedIn(string $installedVersion, string $constraint): ?string
    {
        $version = $installedVersion;
        for ($hop = 0; $hop < self::MAX_HOPS; $hop++) {
            $upper = $this->upperBoundOfMatchingBranch($version, $constraint);
            if ($upper === null) {
                return null;
            }
            if (!$this->affects($upper, $constraint)) {
                return $upper;
            }
            $version = $upper;
        }

        return null;
    }

    /**
     * Upper bound of matching branch.
     *
     * @param string $version
     * @param string $constraint
     * @return string|null
     */
    private function upperBoundOfMatchingBranch(string $version, string $constraint): ?string
    {
        $lowest = null;
        foreach (preg_split('/\s*\|\|?\s*/', trim($constraint)) ?: [] as $branch) {
            if ($branch === '' || !$this->affects($version, $branch)) {
                continue;
            }
            if (preg_match('/(?:^|[\s,])<(?!=)\s*([^\s,|<>=]+)/', $branch, $m) !== 1) {
                continue;
            }
            if ($lowest === null || $this->isLower($m[1], $lowest)) {
                $lowest = $m[1];
            }
        }

        return $lowest;
    }

    /**
     * Is lower.
     *
     * @param string $a
     * @param string $b
     * @return bool
     */
    private function isLower(string $a, string $b): bool
    {
        try {
            return Comparator::lessThan($a, $b);
        } catch (Throwable) {
            return false;
        }
    }
}
