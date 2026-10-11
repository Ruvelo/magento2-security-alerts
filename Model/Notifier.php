<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model;

use Magento\Framework\Escaper;
use Magento\Framework\Mail\Template\TransportBuilder;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Emails findings that nobody has been told about yet: new ones, and ones that have become exploited.
 */
class Notifier
{
    public const TEMPLATE_ID = 'ruvelo_security_alerts_email_template';

    /**
     * __construct.
     *
     * @param Config $config
     * @param FindingStoreInterface $store
     * @param TransportBuilder $transportBuilder
     * @param Escaper $escaper
     * @param LoggerInterface $logger
     */
    public function __construct(
        private readonly Config $config,
        private readonly FindingStoreInterface $store,
        private readonly TransportBuilder $transportBuilder,
        private readonly Escaper $escaper,
        private readonly LoggerInterface $logger
    ) {
    }

    /**
     * Notify pending.
     *
     * @return int How many findings were put in an email
     */
    public function notifyPending(): int
    {
        $recipients = $this->config->recipients();
        if (!$this->config->isEnabled() || $recipients === []) {
            // Nothing is marked, so turning email on later still reports what is open.
            return 0;
        }

        $pending = $this->store->pendingNotification();
        if ($pending === []) {
            return 0;
        }

        // Exploited findings are always sent. The minimum severity filters the rest, and a
        // finding below it is marked as handled so that it is not reconsidered every day.
        $minimum = $this->config->minimumSeverity()->rank();
        $toSend = array_values(array_filter(
            $pending,
            static fn (Finding $f): bool => $f->exploited || $f->severityLevel()->rank() >= $minimum
        ));

        if ($toSend !== []) {
            try {
                $this->send($toSend, $recipients);
            } catch (Throwable $e) {
                $this->logger->error('Ruvelo Security Alerts: the email could not be sent: ' . $e->getMessage());

                return 0;
            }
        }
        $this->store->markNotified($pending);

        return count($toSend);
    }

    /**
     * Send.
     *
     * @param list<Finding> $findings
     * @param list<string> $recipients
     * @return void
     */
    private function send(array $findings, array $recipients): void
    {
        $exploited = array_values(array_filter($findings, static fn (Finding $f): bool => $f->exploited));
        $others = array_values(array_filter($findings, static fn (Finding $f): bool => !$f->exploited));

        $transport = $this->transportBuilder
            ->setTemplateIdentifier(self::TEMPLATE_ID)
            ->setTemplateOptions(['area' => 'adminhtml', 'store' => 0])
            ->setTemplateVars([
                'subject' => $this->subject(count($exploited), count($findings)),
                'exploited_count' => count($exploited),
                'other_count' => count($others),
                'exploited_block' => $this->block($exploited),
                'other_block' => $this->block($others),
            ])
            ->setFromByScope('general')
            ->addTo($recipients)
            ->getTransport();
        $transport->sendMessage();
    }

    /**
     * Subject.
     *
     * @param int $exploited
     * @param int $total
     * @return string
     */
    private function subject(int $exploited, int $total): string
    {
        if ($exploited > 0) {
            return sprintf(
                'Exploited — patch now: %d known %s on your Magento store',
                $exploited,
                $exploited === 1 ? 'vulnerability is being exploited' : 'vulnerabilities are being exploited'
            );
        }

        return sprintf('%d new security %s for your Magento store', $total, $total === 1 ? 'advisory' : 'advisories');
    }

    /**
     * One plain paragraph per finding, escaped here because the template prints it raw.
     *
     * @param list<Finding> $findings
     * @return string
     */
    private function block(array $findings): string
    {
        $html = '';
        foreach ($findings as $finding) {
            $title = $this->escaper->escapeHtml($finding->title);
            if ($finding->link !== null && preg_match('#^https?://#i', $finding->link) === 1) {
                $title = '<a href="' . $this->escaper->escapeUrl($finding->link) . '">' . $title . '</a>';
            }
            $facts = [
                $this->escaper->escapeHtml($finding->package) . ' ' . $this->escaper->escapeHtml($finding->installedVersion),
            ];
            if ($finding->cve !== null) {
                $facts[] = $this->escaper->escapeHtml($finding->cve);
            }
            $facts[] = $this->escaper->escapeHtml($finding->severityLevel()->label())
                . ($finding->severity === null ? ' (not rated)' : '');
            $facts[] = $finding->fixedIn !== null
                ? 'fixed in ' . $this->escaper->escapeHtml($finding->fixedIn)
                : 'no fixed version listed';

            $html .= '<p style="margin:0 0 14px"><strong>' . $title . '</strong><br>'
                . implode(' · ', $facts) . '</p>';
        }

        return $html;
    }
}
