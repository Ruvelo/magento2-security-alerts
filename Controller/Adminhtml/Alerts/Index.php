<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Controller\Adminhtml\Alerts;

use Magento\Backend\App\Action;
use Magento\Backend\Model\View\Result\Page;
use Magento\Framework\App\Action\HttpGetActionInterface;
use Magento\Framework\View\Result\PageFactory;

class Index extends Action implements HttpGetActionInterface
{
    public const ADMIN_RESOURCE = 'Ruvelo_SecurityAlerts::alerts';

    /**
     * __construct.
     *
     * @param Action\Context $context
     * @param PageFactory $pageFactory
     */
    public function __construct(Action\Context $context, private readonly PageFactory $pageFactory)
    {
        parent::__construct($context);
    }

    /**
     * @inheritdoc
     */
    public function execute(): Page
    {
        /** @var Page $page */
        $page = $this->pageFactory->create();
        $page->setActiveMenu('Ruvelo_SecurityAlerts::alerts');
        $page->getConfig()->getTitle()->prepend((string)__('Security alerts'));

        return $page;
    }
}
