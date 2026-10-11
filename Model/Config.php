<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model;

use Magento\Framework\App\Config\ScopeConfigInterface;

class Config
{
    public const XML_ENABLED = 'ruvelo_security_alerts/general/enabled';
    public const XML_EMAILS = 'ruvelo_security_alerts/general/emails';
    public const XML_MIN_SEVERITY = 'ruvelo_security_alerts/general/min_severity';

    /**
     * __construct.
     *
     * @param ScopeConfigInterface $scopeConfig
     */
    public function __construct(private readonly ScopeConfigInterface $scopeConfig)
    {
    }

    /**
     * Is enabled.
     *
     * @return bool
     */
    public function isEnabled(): bool
    {
        return $this->scopeConfig->isSetFlag(self::XML_ENABLED);
    }

    /**
     * Recipients.
     *
     * @return list<string> Valid addresses only
     */
    public function recipients(): array
    {
        $raw = (string)$this->scopeConfig->getValue(self::XML_EMAILS);
        $emails = [];
        foreach (preg_split('/[\s,;]+/', $raw) ?: [] as $candidate) {
            if ($candidate !== '' && filter_var($candidate, FILTER_VALIDATE_EMAIL) !== false) {
                $emails[strtolower($candidate)] ??= $candidate;
            }
        }

        return array_values($emails);
    }

    /**
     * Minimum severity.
     *
     * @return Severity
     */
    public function minimumSeverity(): Severity
    {
        return Severity::tryFrom((string)$this->scopeConfig->getValue(self::XML_MIN_SEVERITY)) ?? Severity::Medium;
    }
}
