<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model\Packages;

use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Exceptions\PackagesUnreadable;
use Ruvelo\SecurityAdvisories\InstalledPackage;
use Ruvelo\SecurityAdvisories\Packages\ComposerLockReader;
use Ruvelo\SecurityAdvisories\Packages\PackageSource;

/**
 * What is installed in a Magento store: the Composer packages in composer.lock, and the Magento
 * core under both names Packagist files its advisories under, at the version Magento reports.
 *
 * A missing or unreadable composer.lock is not fatal: the core is still checked, and the reason
 * is kept in $warnings.
 */
class MagentoPackages implements PackageSource
{
    /** The two names Packagist files Magento core advisories under. */
    public const CORE_PACKAGES = ['magento/product-community-edition', 'magento/community-edition'];

    /**
     * Magento and Mage-OS ship hundreds of modules whose version is the release they came in.
     * The core is checked once, by its edition package, so these are not sent anywhere.
     */
    private const SKIPPED = '#^(magento|mage-os)/(module|theme|language|framework-)[a-z0-9_-]*$#';

    /** @var list<string> */
    private array $warnings = [];

    /**
     * __construct.
     *
     * @param string $lockPath
     * @param string|null $coreVersion What Magento says it is (Mage-OS reports its Magento base version); null when unreadable
     */
    public function __construct(private readonly string $lockPath, private readonly ?string $coreVersion)
    {
    }

    /**
     * Whether there is anything to look up at all.
     *
     * @return bool
     */
    public function hasAnything(): bool
    {
        return $this->coreVersion !== null || is_file($this->lockPath);
    }

    /**
     * Why part of the store could not be read, as of the last call to packages().
     *
     * @return list<string>
     */
    public function warnings(): array
    {
        return $this->warnings;
    }

    /**
     * @inheritdoc
     */
    public function ecosystem(): Ecosystem
    {
        return Ecosystem::Composer;
    }

    /**
     * @inheritdoc
     */
    public function describe(): string
    {
        return 'composer.lock at ' . $this->lockPath;
    }

    /**
     * @inheritdoc
     */
    public function isRequired(): bool
    {
        return false;
    }

    /**
     * Packages.
     *
     * @return list<InstalledPackage>
     */
    public function packages(): array
    {
        $this->warnings = [];
        $packages = [];

        try {
            $locked = (new ComposerLockReader($this->lockPath, false))->packages();
            if ($locked === null) {
                $this->warnings[] = 'composer.lock was not found in the Magento root, so extensions cannot be checked.';
            }
            foreach ($locked ?? [] as $package) {
                if (preg_match(self::SKIPPED, $package->name) !== 1 && !in_array($package->name, self::CORE_PACKAGES, true)) {
                    $packages[] = $package;
                }
            }
        } catch (PackagesUnreadable $e) {
            $this->warnings[] = $e->getMessage();
        }

        if ($this->coreVersion === null) {
            $this->warnings[] = 'The Magento version could not be read, so core advisories were not checked.';
        } else {
            foreach (self::CORE_PACKAGES as $name) {
                $packages[] = new InstalledPackage(Ecosystem::Composer, $name, $this->coreVersion);
            }
        }

        return $packages;
    }
}
