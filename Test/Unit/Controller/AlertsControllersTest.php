<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Controller;

use Magento\Backend\App\Action\Context;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Controller\Result\Redirect;
use Magento\Framework\Controller\Result\RedirectFactory;
use Magento\Framework\Message\ManagerInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Controller\Adminhtml\Alerts\Check;
use Ruvelo\SecurityAlerts\Controller\Adminhtml\Alerts\Dismiss;
use Ruvelo\SecurityAlerts\Exception\SourceException;
use Ruvelo\SecurityAlerts\Model\Changes;
use Ruvelo\SecurityAlerts\Model\CheckOutcome;
use Ruvelo\SecurityAlerts\Model\Checker;
use Ruvelo\SecurityAlerts\Model\ScanResult;
use Ruvelo\SecurityAlerts\Test\Unit\Fake\Findings;
use Ruvelo\SecurityAlerts\Test\Unit\Fake\InMemoryStore;

class AlertsControllersTest extends TestCase
{
    /** @var ManagerInterface&MockObject */
    private ManagerInterface $messages;

    /** @var Context&MockObject */
    private Context $context;

    /** @var RedirectFactory&MockObject */
    private RedirectFactory $redirects;

    /** @var array<string, mixed> */
    private array $params = [];

    protected function setUp(): void
    {
        $this->messages = $this->createMock(ManagerInterface::class);
        $request = $this->createMock(RequestInterface::class);
        $request->method('getParam')->willReturnCallback(fn (string $key): mixed => $this->params[$key] ?? null);
        $this->context = $this->createMock(Context::class);
        $this->context->method('getMessageManager')->willReturn($this->messages);
        $this->context->method('getRequest')->willReturn($request);

        $redirect = $this->createMock(Redirect::class);
        $redirect->method('setPath')->willReturnSelf();
        $this->redirects = $this->createMock(RedirectFactory::class);
        $this->redirects->method('create')->willReturn($redirect);
    }

    private function checker(ScanResult|SourceException $outcome): Checker
    {
        $checker = $this->createMock(Checker::class);
        if ($outcome instanceof SourceException) {
            $checker->method('run')->willThrowException($outcome);
        } else {
            $checker->method('run')->willReturn(new CheckOutcome($outcome, new Changes([], [], 0), 0));
        }

        return $checker;
    }

    public function testActionsThatChangeThingsArePostOnly(): void
    {
        $this->assertContains(HttpPostActionInterface::class, class_implements(Check::class));
        $this->assertContains(HttpPostActionInterface::class, class_implements(Dismiss::class));
    }

    public function testCheckNowOnACleanStore(): void
    {
        $this->messages->expects($this->once())->method('addSuccessMessage');

        (new Check($this->context, $this->checker(new ScanResult([], [], 5)), $this->redirects))->execute();
    }

    public function testCheckNowWithExploitedFindingsWarns(): void
    {
        $this->messages->expects($this->once())->method('addWarningMessage')
            ->with($this->callback(static fn ($m): bool => str_contains((string)$m, '1 of them exploited')));

        $result = new ScanResult([Findings::make(exploited: true), Findings::make(advisory: 'PKSA-2')], [], 5);
        (new Check($this->context, $this->checker($result), $this->redirects))->execute();
    }

    public function testCheckNowWithOnlyUnexploitedFindingsIsANotice(): void
    {
        $this->messages->expects($this->once())->method('addNoticeMessage');

        (new Check($this->context, $this->checker(new ScanResult([Findings::make()], [], 5)), $this->redirects))->execute();
    }

    public function testCheckNowShowsAnOutageAsAnError(): void
    {
        $this->messages->expects($this->once())->method('addErrorMessage')
            ->with($this->callback(static fn ($m): bool => str_contains((string)$m, 'Packagist is down.')));

        (new Check($this->context, $this->checker(new SourceException('Packagist is down.')), $this->redirects))
            ->execute();
    }

    public function testDismissMarksTheFinding(): void
    {
        $store = new InMemoryStore();
        $store->insert(Findings::make(exploited: true));
        $this->params = ['id' => '1'];
        $this->messages->expects($this->once())->method('addSuccessMessage');

        (new Dismiss($this->context, $store, $this->redirects))->execute();

        $this->assertTrue($store->all()[0]->dismissed);
    }

    public function testDismissWithoutAnIdSaysSo(): void
    {
        $store = new InMemoryStore();
        $store->insert(Findings::make(exploited: true));
        $this->messages->expects($this->once())->method('addErrorMessage');

        (new Dismiss($this->context, $store, $this->redirects))->execute();

        $this->assertFalse($store->all()[0]->dismissed);
    }
}
