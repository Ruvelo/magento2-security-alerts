<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Fake;

use GuzzleHttp\Psr7\Response;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

/**
 * Packagist, CISA and Valtry's Advisory API, from the fixtures in _files. Never touches the network.
 *
 * Like the real ones, they only answer for the package names they are asked about. Valtry's
 * answers are signed with a key made for the test, which the CoreFactory is told to trust.
 */
class FakeHttp implements ClientInterface
{
    /** @var list<string> "METHOD url body" of every request made */
    public array $requests = [];

    public bool $packagistDown = false;

    public bool $kevDown = false;

    public bool $valtryDown = false;

    /** @var (callable(string, string): array{0: string, 1: string})|null Gets Valtry's body and signature header, returns both */
    public $tamper = null;

    /** @var non-empty-string */
    private string $secretKey;

    private string $publicKey;

    public function __construct()
    {
        $pair = sodium_crypto_sign_keypair();
        $this->secretKey = sodium_crypto_sign_secretkey($pair);
        $this->publicKey = base64_encode(sodium_crypto_sign_publickey($pair));
    }

    /**
     * @return array<string, string> The keys Valtry's answers are signed with
     */
    public function valtryKeys(): array
    {
        return ['test-1' => $this->publicKey];
    }

    /**
     * Requests to a host.
     *
     * @param string $host
     * @return list<string>
     */
    public function requestsTo(string $host): array
    {
        return array_values(array_filter($this->requests, static fn (string $r): bool => str_contains($r, $host)));
    }

    /**
     * @inheritdoc
     */
    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $url = (string)$request->getUri();
        $body = (string)$request->getBody();
        $this->requests[] = $request->getMethod() . ' ' . $url . ' ' . $body;

        return match (true) {
            str_contains($url, 'packagist.org') => $this->packagist($body),
            str_contains($url, 'cisa.gov') => $this->kev(),
            str_contains($url, 'valtry') => $this->valtry($body),
            default => throw new RuntimeException('Unexpected request to ' . $url),
        };
    }

    /**
     * Packagist.
     *
     * @param string $form
     * @return ResponseInterface
     */
    private function packagist(string $form): ResponseInterface
    {
        if ($this->packagistDown) {
            throw $this->unreachable('Packagist');
        }
        parse_str($form, $query);
        $asked = is_array($query['packages'] ?? null) ? $query['packages'] : [];

        return new Response(
            200,
            ['Content-Type' => 'application/json'],
            (string)json_encode(['advisories' => (object)array_intersect_key($this->advisories(), array_flip($asked))])
        );
    }

    /**
     * Kev.
     *
     * @return ResponseInterface
     */
    private function kev(): ResponseInterface
    {
        if ($this->kevDown) {
            return new Response(503);
        }

        return new Response(200, ['Content-Type' => 'application/json'], (string)file_get_contents(__DIR__ . '/../_files/kev.json'));
    }

    /**
     * Valtry.
     *
     * @param string $json
     * @return ResponseInterface
     */
    private function valtry(string $json): ResponseInterface
    {
        if ($this->valtryDown) {
            throw $this->unreachable('Valtry');
        }
        $request = json_decode($json, true);
        $advisories = [];
        foreach ($request['packages'] ?? [] as $package) {
            $advisories[$package['ecosystem'] . ':' . $package['name']] = array_map(
                fn (array $a): array => $this->valtryItem($a),
                $this->advisories()[$package['name']] ?? []
            );
        }
        $body = (string)json_encode([
            'v' => 1,
            'nonce' => $request['nonce'] ?? null,
            'advisories' => (object)$advisories,
            'stale' => false,
            'stale_ecosystems' => [],
        ], JSON_UNESCAPED_SLASHES);
        $header = 'ed25519=' . base64_encode(sodium_crypto_sign_detached($body, $this->secretKey)) . '; kid=test-1';
        if ($this->tamper !== null) {
            [$body, $header] = ($this->tamper)($body, $header);
        }

        return new Response(200, ['Content-Type' => 'application/json', 'X-Valtry-Signature' => $header], $body);
    }

    /**
     * Valtry item.
     *
     * @param array<string, mixed> $a A Packagist record
     * @return array<string, mixed>
     */
    private function valtryItem(array $a): array
    {
        $kev = $this->kevEntry($a['cve'] ?? null);

        return [
            'id' => $a['advisoryId'], 'source' => 'packagist', 'title' => $a['title'], 'link' => $a['link'],
            'cve' => $a['cve'] ?? null, 'aliases' => [], 'severity' => $a['severity'] ?? null,
            'affected' => $a['affectedVersions'], 'fixed_in' => [], 'exploited' => $kev !== null, 'kev' => $kev,
            'published_at' => str_replace(' ', 'T', (string)$a['reportedAt']) . 'Z', 'updated_at' => null, 'attribution' => null,
        ];
    }

    /**
     * Kev entry.
     *
     * @param string|null $cve
     * @return array<string, mixed>|null
     */
    private function kevEntry(?string $cve): ?array
    {
        $catalogue = json_decode((string)file_get_contents(__DIR__ . '/../_files/kev.json'), true);
        foreach ($catalogue['vulnerabilities'] as $entry) {
            if ($cve !== null && strtoupper($entry['cveID']) === strtoupper($cve)) {
                return [
                    'cve' => strtoupper($entry['cveID']),
                    'name' => $entry['vulnerabilityName'],
                    'date_added' => $entry['dateAdded'],
                    'due_date' => $entry['dueDate'] ?? null,
                    'ransomware' => strtolower($entry['knownRansomwareCampaignUse'] ?? '') === 'known',
                ];
            }
        }

        return null;
    }

    /**
     * Advisories.
     *
     * @return array<string, list<array<string, mixed>>>
     */
    private function advisories(): array
    {
        return json_decode((string)file_get_contents(__DIR__ . '/../_files/advisories.json'), true)['advisories'];
    }

    /**
     * Unreachable.
     *
     * @param string $who
     * @return NetworkExceptionInterface
     */
    private function unreachable(string $who): NetworkExceptionInterface
    {
        return new class ($who . ' is down.') extends RuntimeException implements NetworkExceptionInterface {
            /**
             * @inheritdoc
             */
            public function getRequest(): RequestInterface
            {
                return new \GuzzleHttp\Psr7\Request('GET', 'https://down.test/');
            }
        };
    }
}
