<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model;

use GuzzleHttp\Psr7\HttpFactory;
use Magento\Framework\App\Filesystem\DirectoryList;
use Psr\Http\Client\ClientInterface;
use Psr\SimpleCache\CacheInterface;
use Ruvelo\SecurityAdvisories\Cache\FileCache;
use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Cache\Ttls;
use Ruvelo\SecurityAdvisories\Http\CurlClient;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\Packages\PackageSource;
use Ruvelo\SecurityAdvisories\Scanner as Core;
use Ruvelo\SecurityAdvisories\Sources\FallbackAdvisorySource;
use Ruvelo\SecurityAdvisories\Sources\KevCatalogue;
use Ruvelo\SecurityAdvisories\Sources\PackagistAdvisorySource;
use Ruvelo\SecurityAdvisories\Valtry\ValtryAdvisorySource;

/**
 * Wires the shared core, ruvelo/security-advisories, to Magento: the core's own cURL client
 * (Magento's stack offers no single PSR-18 client to count on), PSR-17 factories from
 * guzzlehttp/psr7 (which Magento ships), and a file cache under var/.
 */
class CoreFactory
{
    public const USER_AGENT = 'Ruvelo-SecurityAlerts/1.1 (+https://github.com/Ruvelo/magento2-security-alerts)';

    private const TIMEOUT_SECONDS = 20.0;

    /**
     * __construct.
     *
     * @param DirectoryList $directoryList
     * @param ClientInterface|null $client A PSR-18 client to use instead of the cURL one (tests, a proxy)
     * @param CacheInterface|null $cache A PSR-16 cache to use instead of the files under var/
     * @param array<string, string>|null $valtryKeys Keys to verify Valtry's answers with, instead of the pinned ones (tests only)
     */
    public function __construct(
        private readonly DirectoryList $directoryList,
        private readonly ?ClientInterface $client = null,
        private readonly ?CacheInterface $cache = null,
        private readonly ?array $valtryKeys = null
    ) {
    }

    /**
     * Create.
     *
     * @param PackageSource $packages
     * @param string $source Config::SOURCE_VALTRY or Config::SOURCE_PUBLIC
     * @return Core
     */
    public function create(PackageSource $packages, string $source): Core
    {
        $factory = new HttpFactory();
        $http = new JsonClient(
            $this->client ?? new CurlClient($factory, $factory, self::TIMEOUT_SECONDS),
            $factory,
            $factory,
            self::USER_AGENT,
            2
        );
        $cache = new ResponseCache($this->cache ?? new FileCache($this->cacheDirectory()), new Ttls());

        $public = [new PackagistAdvisorySource($http, $cache)];
        $viaValtry = Core::source($source) === Core::SOURCE_VALTRY;
        $advisories = $viaValtry
            ? [new FallbackAdvisorySource(
                new ValtryAdvisorySource(
                    new JsonClient(
                        $this->client ?? new CurlClient($factory, $factory, ValtryAdvisorySource::DEADLINE, 3.0),
                        $factory,
                        $factory,
                        self::USER_AGENT,
                        1
                    ),
                    $cache,
                    ValtryAdvisorySource::URL,
                    $this->valtryKeys
                ),
                $public
            )]
            : $public;

        return new Core([$packages], $advisories, new KevCatalogue($http, $cache));
    }

    /**
     * Cache directory.
     *
     * @return string
     */
    private function cacheDirectory(): string
    {
        return $this->directoryList->getPath(DirectoryList::VAR_DIR) . '/ruvelo_security_alerts/cache';
    }
}
