<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Fake;

use Ruvelo\SecurityAlerts\Exception\SourceException;
use Ruvelo\SecurityAlerts\Model\Http\FetcherInterface;
use Ruvelo\SecurityAlerts\Model\Source\AdvisoryClient;
use Ruvelo\SecurityAlerts\Model\Source\KevCatalogue;

/**
 * Answers Packagist and CISA from the fixtures in _files. Never touches the network.
 *
 * Like Packagist, it only answers for the package names it is asked about.
 */
class FakeFetcher implements FetcherInterface
{
    /** @var list<string> */
    public array $requests = [];

    public bool $packagistDown = false;

    public bool $kevDown = false;

    public function get(string $url): string
    {
        $this->requests[] = 'GET ' . $url;
        if ($url !== KevCatalogue::URL || $this->kevDown) {
            throw new SourceException('CISA is down.');
        }

        return (string)file_get_contents(__DIR__ . '/../_files/kev.json');
    }

    public function postForm(string $url, string $formBody): string
    {
        $this->requests[] = 'POST ' . $url . ' ' . $formBody;
        if ($url !== AdvisoryClient::ENDPOINT || $this->packagistDown) {
            throw new SourceException('Packagist is down.');
        }
        parse_str($formBody, $query);
        $asked = is_array($query['packages'] ?? null) ? $query['packages'] : [];
        $all = json_decode((string)file_get_contents(__DIR__ . '/../_files/advisories.json'), true);

        return (string)json_encode(['advisories' => array_intersect_key($all['advisories'], array_flip($asked))]);
    }
}
