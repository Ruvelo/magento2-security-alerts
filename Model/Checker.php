<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model;

use Magento\Framework\Event\ManagerInterface;
use Magento\Framework\FlagManager;
use Ruvelo\SecurityAlerts\Exception\SourceException;

/**
 * One full check: scan, store what changed, tell the people who asked to be told.
 */
class Checker
{
    public const EVENT = 'ruvelo_security_alerts_found';
    public const FLAG_LAST_CHECK = 'ruvelo_security_alerts_last_check';

    /**
     * __construct.
     *
     * @param Scanner $scanner
     * @param Reconciler $reconciler
     * @param Notifier $notifier
     * @param ManagerInterface $events
     * @param FlagManager $flags
     */
    public function __construct(
        private readonly Scanner $scanner,
        private readonly Reconciler $reconciler,
        private readonly Notifier $notifier,
        private readonly ManagerInterface $events,
        private readonly FlagManager $flags
    ) {
    }

    /**
     * Run.
     *
     * @return CheckOutcome
     * @throws SourceException
     */
    public function run(): CheckOutcome
    {
        $result = $this->scanner->scan();
        $changes = $this->reconciler->reconcile($result->findings);
        $this->flags->saveFlag(self::FLAG_LAST_CHECK, gmdate('Y-m-d H:i:s'));

        if ($result->findings !== []) {
            $this->events->dispatch(self::EVENT, [
                'findings' => $result->findings,
                'new_findings' => array_merge($changes->new, $changes->becameExploited),
                'result' => $result,
            ]);
        }

        return new CheckOutcome($result, $changes, $this->notifier->notifyPending());
    }
}
