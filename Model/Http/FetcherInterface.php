<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model\Http;

use Ruvelo\SecurityAlerts\Exception\SourceException;

interface FetcherInterface
{
    /**
     * Get.
     *
     * @param string $url
     * @return string Response body
     * @throws SourceException
     */
    public function get(string $url): string;

    /**
     * Post form.
     *
     * @param string $url
     * @param string $formBody An application/x-www-form-urlencoded body
     * @return string Response body
     * @throws SourceException
     */
    public function postForm(string $url, string $formBody): string;
}
