<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Controller\Adminhtml\Alerts;

use Magento\Backend\App\Action;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\Controller\Result\Redirect;
use Magento\Framework\Controller\Result\RedirectFactory;
use Ruvelo\SecurityAlerts\Model\FindingStoreInterface;

/**
 * Dismisses one finding. A dismissed finding stays listed, stops counting for the admin
 * message and email, and comes back on its own if it later becomes exploited.
 */
class Dismiss extends Action implements HttpPostActionInterface
{
    public const ADMIN_RESOURCE = 'Ruvelo_SecurityAlerts::alerts';

    /**
     * __construct.
     *
     * @param Action\Context $context
     * @param FindingStoreInterface $store
     * @param RedirectFactory $redirectFactory
     */
    public function __construct(
        Action\Context $context,
        private readonly FindingStoreInterface $store,
        private readonly RedirectFactory $redirectFactory
    ) {
        parent::__construct($context);
    }

    /**
     * @inheritdoc
     */
    public function execute(): Redirect
    {
        $id = (int)$this->getRequest()->getParam('id');
        if ($id > 0) {
            $this->store->dismiss($id);
            $this->messageManager->addSuccessMessage(__('Dismissed. It will come back if it becomes exploited.'));
        } else {
            $this->messageManager->addErrorMessage(__('That finding could not be found.'));
        }

        return $this->redirectFactory->create()->setPath('*/*/index');
    }
}
