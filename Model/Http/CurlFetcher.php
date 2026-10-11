<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model\Http;

use Magento\Framework\HTTP\ClientInterface;
use Ruvelo\SecurityAlerts\Exception\SourceException;
use Throwable;

/**
 * Plain HTTPS requests through Magento's own HTTP client.
 *
 * Nothing is sent but the URL and, for Packagist, the package names and nothing else.
 */
class CurlFetcher implements FetcherInterface
{
    private const TIMEOUT_SECONDS = 20;

    /**
     * __construct.
     *
     * @param ClientInterface $client Not shared, see etc/di.xml
     */
    public function __construct(private readonly ClientInterface $client)
    {
    }

    /**
     * @inheritdoc
     */
    public function get(string $url): string
    {
        return $this->request($url, null);
    }

    /**
     * @inheritdoc
     */
    public function postForm(string $url, string $formBody): string
    {
        return $this->request($url, $formBody);
    }

    /**
     * Request.
     *
     * @param string $url
     * @param string|null $body
     * @return string
     * @throws SourceException
     */
    private function request(string $url, ?string $body): string
    {
        try {
            $this->client->setTimeout(self::TIMEOUT_SECONDS);
            $this->client->addHeader('User-Agent', 'Ruvelo-SecurityAlerts/1.0 (+https://github.com/Ruvelo/magento2-security-alerts)');
            $this->client->addHeader('Accept', 'application/json');
            if ($body === null) {
                $this->client->get($url);
            } else {
                $this->client->addHeader('Content-Type', 'application/x-www-form-urlencoded');
                $this->client->post($url, $body);
            }
            $status = $this->client->getStatus();
            $response = $this->client->getBody();
        } catch (Throwable $e) {
            throw new SourceException(sprintf('Could not reach %s: %s', $url, $e->getMessage()), 0, $e);
        }

        if ($status !== 200) {
            throw new SourceException(sprintf('%s answered with HTTP %d.', $url, $status));
        }

        return $response;
    }
}
