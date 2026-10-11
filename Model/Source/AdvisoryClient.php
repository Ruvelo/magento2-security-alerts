<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model\Source;

use Ruvelo\SecurityAlerts\Exception\SourceException;
use Ruvelo\SecurityAlerts\Model\Http\FetcherInterface;

/**
 * Asks Packagist's security advisories API about a list of package names.
 *
 * Only package names leave the server. Versions are matched locally.
 */
class AdvisoryClient
{
    public const ENDPOINT = 'https://packagist.org/api/security-advisories/';

    private const CHUNK = 100;

    /**
     * __construct.
     *
     * @param FetcherInterface $fetcher
     */
    public function __construct(private readonly FetcherInterface $fetcher)
    {
    }

    /**
     * Fetch.
     *
     * @param list<string> $packages
     * @return array<string, list<array<string, mixed>>> Advisories per package name
     * @throws SourceException
     */
    public function fetch(array $packages): array
    {
        $advisories = [];
        foreach (array_chunk(array_values(array_unique($packages)), self::CHUNK) as $chunk) {
            $body = implode('&', array_map(
                static fn (string $name): string => 'packages[]=' . rawurlencode($name),
                $chunk
            ));
            foreach ($this->decode($this->fetcher->postForm(self::ENDPOINT, $body)) as $name => $list) {
                $advisories[$name] = array_merge($advisories[$name] ?? [], $list);
            }
        }

        return $advisories;
    }

    /**
     * Decode.
     *
     * @param string $json
     * @return array<string, list<array<string, mixed>>>
     * @throws SourceException
     */
    private function decode(string $json): array
    {
        $data = json_decode($json, true);
        if (!is_array($data) || !isset($data['advisories']) || !is_array($data['advisories'])) {
            throw new SourceException('Packagist answered with something that is not an advisories list.');
        }

        $result = [];
        foreach ($data['advisories'] as $name => $list) {
            if (!is_array($list)) {
                continue;
            }
            $result[(string)$name] = array_values(array_filter($list, 'is_array'));
        }

        return $result;
    }
}
