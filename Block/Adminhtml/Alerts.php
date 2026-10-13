<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Block\Adminhtml;

use Magento\Backend\Block\Template;
use Magento\Backend\Block\Template\Context;
use Magento\Framework\FlagManager;
use Ruvelo\SecurityAlerts\Model\Checker;
use Ruvelo\SecurityAlerts\Model\Finding;
use Ruvelo\SecurityAlerts\Model\FindingStoreInterface;
use Ruvelo\SecurityAlerts\Model\ScanResult;

/**
 * Data for the security alerts page. The page is a plain server-rendered table: see the README
 * for why it is not a UI component grid.
 */
class Alerts extends Template
{
    /**
     * __construct.
     *
     * @param Context $context
     * @param FindingStoreInterface $store
     * @param FlagManager $flags
     * @param array<string, mixed> $data
     */
    public function __construct(
        Context $context,
        private readonly FindingStoreInterface $store,
        private readonly FlagManager $flags,
        array $data = []
    ) {
        parent::__construct($context, $data);
    }

    /**
     * Get findings.
     *
     * @return list<Finding>
     */
    public function getFindings(): array
    {
        return $this->store->all();
    }

    /**
     * Get last check.
     *
     * @return string|null UTC time of the last finished check
     */
    public function getLastCheck(): ?string
    {
        $value = $this->flags->getFlagData(Checker::FLAG_LAST_CHECK);

        return is_string($value) ? $value : null;
    }

    /**
     * Where the advisories of the last check came from, in words.
     *
     * @return string|null Null before the first check
     */
    public function getLastSource(): ?string
    {
        $value = $this->flags->getFlagData(Checker::FLAG_LAST_SOURCE);

        return is_string($value) && $value !== '' ? ScanResult::label($value) : null;
    }

    /**
     * Get check url.
     *
     * @return string
     */
    public function getCheckUrl(): string
    {
        return $this->getUrl('*/*/check');
    }

    /**
     * Get dismiss url.
     *
     * @return string
     */
    public function getDismissUrl(): string
    {
        return $this->getUrl('*/*/dismiss');
    }

    /**
     * Is safe link.
     *
     * @param string $url
     * @return bool Only http(s) links are rendered as links
     */
    public function isSafeLink(string $url): bool
    {
        return preg_match('#^https?://#i', $url) === 1;
    }
}
