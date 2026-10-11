<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model;

use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\Exception\FileSystemException;
use Magento\Framework\Filesystem\Driver\File;
use Ruvelo\SecurityAlerts\Exception\SourceException;

/**
 * Reads the exact installed versions from composer.lock at the Magento root.
 */
class ComposerLock
{
    /**
     * Magento and Mage-OS ship hundreds of modules whose version is the release they came in.
     * The core is checked once, by its edition package, so these are not sent anywhere.
     */
    private const SKIPPED = '#^(magento|mage-os)/(module|theme|language|framework-)[a-z0-9_-]*$#';

    /**
     * __construct.
     *
     * @param DirectoryList $directoryList
     * @param File $file
     */
    public function __construct(
        private readonly DirectoryList $directoryList,
        private readonly File $file
    ) {
    }

    /**
     * Packages.
     *
     * @return array<string, string> Package name => installed version
     * @throws SourceException
     */
    public function packages(): array
    {
        $path = $this->directoryList->getRoot() . '/composer.lock';
        try {
            if (!$this->file->isExists($path)) {
                throw new SourceException('composer.lock was not found in the Magento root, so extensions cannot be checked.');
            }
            $json = $this->file->fileGetContents($path);
        } catch (FileSystemException $e) {
            throw new SourceException('composer.lock could not be read: ' . $e->getMessage(), 0, $e);
        }

        $lock = json_decode($json, true);
        if (!is_array($lock) || !isset($lock['packages']) || !is_array($lock['packages'])) {
            throw new SourceException('composer.lock is not valid JSON.');
        }

        $packages = [];
        foreach ($lock['packages'] as $package) {
            if (!is_array($package) || !isset($package['name'], $package['version'])
                || !is_string($package['name']) || !is_string($package['version'])
                || preg_match(self::SKIPPED, $package['name']) === 1
            ) {
                continue;
            }
            $packages[$package['name']] = $package['version'];
        }

        return $packages;
    }
}
