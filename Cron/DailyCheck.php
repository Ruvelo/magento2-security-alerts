<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Cron;

use Psr\Log\LoggerInterface;
use Ruvelo\SecurityAlerts\Exception\SourceException;
use Ruvelo\SecurityAlerts\Model\Checker;
use Ruvelo\SecurityAlerts\Model\Config;

class DailyCheck
{
    /**
     * __construct.
     *
     * @param Config $config
     * @param Checker $checker
     * @param LoggerInterface $logger
     */
    public function __construct(
        private readonly Config $config,
        private readonly Checker $checker,
        private readonly LoggerInterface $logger
    ) {
    }

    /**
     * Execute.
     *
     * @return void
     */
    public function execute(): void
    {
        if (!$this->config->isEnabled()) {
            return;
        }
        try {
            $this->checker->run();
        } catch (SourceException $e) {
            $this->logger->warning('Ruvelo Security Alerts: ' . $e->getMessage());
        }
    }
}
