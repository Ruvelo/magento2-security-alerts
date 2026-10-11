<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Controller\Adminhtml\Alerts;

use Magento\Backend\App\Action;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\Controller\Result\Redirect;
use Magento\Framework\Controller\Result\RedirectFactory;
use Ruvelo\SecurityAlerts\Exception\SourceException;
use Ruvelo\SecurityAlerts\Model\Checker;

/**
 * "Check now". POST only, so Magento's CSRF validator requires the form key.
 */
class Check extends Action implements HttpPostActionInterface
{
    public const ADMIN_RESOURCE = 'Ruvelo_SecurityAlerts::alerts';

    /**
     * __construct.
     *
     * @param Action\Context $context
     * @param Checker $checker
     * @param RedirectFactory $redirectFactory
     */
    public function __construct(
        Action\Context $context,
        private readonly Checker $checker,
        private readonly RedirectFactory $redirectFactory
    ) {
        parent::__construct($context);
    }

    /**
     * @inheritdoc
     */
    public function execute(): Redirect
    {
        try {
            $outcome = $this->checker->run();
            $exploited = count($outcome->result->exploited());
            $total = count($outcome->result->findings);
            if ($total === 0) {
                $this->messageManager->addSuccessMessage(__('No known vulnerabilities found.'));
            } elseif ($exploited > 0) {
                $this->messageManager->addWarningMessage(
                    __('%1 findings, %2 of them exploited in the wild.', $total, $exploited)
                );
            } else {
                $this->messageManager->addNoticeMessage(__('%1 findings, none known to be exploited.', $total));
            }
            foreach ($outcome->result->warnings as $warning) {
                $this->messageManager->addWarningMessage($warning);
            }
        } catch (SourceException $e) {
            $this->messageManager->addErrorMessage(
                __('The check could not finish: %1 Try again later, or run bin/magento ruvelo:security-alerts:check.', $e->getMessage())
            );
        }

        return $this->redirectFactory->create()->setPath('*/*/index');
    }
}
