<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Fake;

use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\App\ProductMetadataInterface;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Model\Config;
use Ruvelo\SecurityAlerts\Model\CoreFactory;
use Ruvelo\SecurityAlerts\Model\Scanner;

/**
 * A Scanner over a made-up Magento root, talking to FakeHttp.
 */
class ScannerFactory
{
    /**
     * Build.
     *
     * @param TestCase $test
     * @param FakeHttp $http
     * @param string $root A directory that holds (or lacks) composer.lock
     * @param string $magentoVersion What ProductMetadataInterface reports
     * @param string $source The configured advisory source
     * @return Scanner
     */
    public static function build(TestCase $test, FakeHttp $http, string $root, string $magentoVersion, string $source = 'valtry'): Scanner
    {
        $metadata = (new Mocker($test))->mock(ProductMetadataInterface::class);
        $metadata->method('getVersion')->willReturn($magentoVersion);
        $directories = (new Mocker($test))->mock(DirectoryList::class);
        $directories->method('getRoot')->willReturn($root);
        $config = (new Mocker($test))->mock(Config::class);
        $config->method('advisorySource')->willReturn($source);

        return new Scanner(
            $metadata,
            $directories,
            new CoreFactory($directories, $http, new ArrayCache(), $http->valtryKeys()),
            $config
        );
    }

    /**
     * A directory with a composer.lock of these packages.
     *
     * @param array<string, string>|null $packages Name => version; null for no composer.lock at all
     * @param string|null $raw What to write instead, to make it unreadable
     * @return string
     */
    public static function root(?array $packages, ?string $raw = null): string
    {
        $dir = sys_get_temp_dir() . '/ruvelo-sa-' . bin2hex(random_bytes(6));
        mkdir($dir);
        if ($packages !== null || $raw !== null) {
            $lock = ['packages' => array_map(
                static fn (string $name, string $version): array => ['name' => $name, 'version' => $version],
                array_keys($packages ?? []),
                array_values($packages ?? [])
            )];
            file_put_contents($dir . '/composer.lock', $raw ?? json_encode($lock));
        }

        return $dir;
    }
}
