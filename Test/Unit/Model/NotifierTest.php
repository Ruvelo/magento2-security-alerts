<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Model;

use Ruvelo\SecurityAlerts\Test\Unit\Fake\Escapers;
use Magento\Framework\Mail\TransportInterface;
use Magento\Framework\Mail\Template\TransportBuilder;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Ruvelo\SecurityAlerts\Model\Config;
use Ruvelo\SecurityAlerts\Model\Notifier;
use Ruvelo\SecurityAlerts\Model\Severity;
use Ruvelo\SecurityAlerts\Test\Unit\Fake\Findings;
use Ruvelo\SecurityAlerts\Test\Unit\Fake\InMemoryStore;

class NotifierTest extends TestCase
{
    private InMemoryStore $store;

    /** @var Config&MockObject */
    private Config $config;

    /** @var TransportBuilder&MockObject */
    private TransportBuilder $builder;

    /** @var TransportInterface&MockObject */
    private TransportInterface $transport;

    /** @var array<string, mixed> */
    private array $vars = [];

    /** @var list<string> */
    private array $to = [];

    protected function setUp(): void
    {
        $this->store = new InMemoryStore();
        $this->config = $this->createMock(Config::class);
        $this->config->method('isEnabled')->willReturn(true);
        $this->config->method('recipients')->willReturn(['ops@example.com']);
        $this->config->method('minimumSeverity')->willReturn(Severity::High);

        $this->transport = $this->createMock(TransportInterface::class);
        $this->builder = $this->createMock(TransportBuilder::class);
        foreach (['setTemplateIdentifier', 'setTemplateOptions', 'setFromByScope'] as $method) {
            $this->builder->method($method)->willReturnSelf();
        }
        $this->builder->method('setTemplateVars')->willReturnCallback(function (array $vars): TransportBuilder {
            $this->vars = $vars;

            return $this->builder;
        });
        $this->builder->method('addTo')->willReturnCallback(function ($address): TransportBuilder {
            $this->to = (array)$address;

            return $this->builder;
        });
        $this->builder->method('getTransport')->willReturn($this->transport);
    }

    private function notifier(): Notifier
    {
        return new Notifier(
            $this->config,
            $this->store,
            $this->builder,
            Escapers::make(),
            $this->createMock(LoggerInterface::class)
        );
    }

    public function testExploitedComesFirstAndIsLabelled(): void
    {
        $this->store->insert(Findings::make(advisory: 'PKSA-1', title: 'Quiet one'));
        $this->store->insert(Findings::make(advisory: 'PKSA-2', exploited: true, title: 'Loud one'));
        $this->transport->expects($this->once())->method('sendMessage');

        $sent = $this->notifier()->notifyPending();

        $this->assertSame(2, $sent);
        $this->assertSame(['ops@example.com'], $this->to);
        $this->assertStringContainsString('Exploited — patch now', $this->vars['subject']);
        $this->assertSame(1, $this->vars['exploited_count']);
        $this->assertSame(1, $this->vars['other_count']);
        $this->assertSame('1', $this->vars['has_exploited']);
        $this->assertSame('1', $this->vars['has_other']);
        $this->assertStringContainsString('Loud one', $this->vars['exploited_block']);
        $this->assertStringNotContainsString('Quiet one', $this->vars['exploited_block']);
        $this->assertStringContainsString('Quiet one', $this->vars['other_block']);
    }

    public function testAnEmptySectionIsSwitchedOffWithAnEmptyString(): void
    {
        // {{depend}} hides a block when the value == '', which PHP 8 says is false for the integer 0.
        $this->store->insert(Findings::make(advisory: 'PKSA-1', title: 'Quiet one'));

        $this->notifier()->notifyPending();

        $this->assertSame('', $this->vars['has_exploited']);
        $this->assertSame('1', $this->vars['has_other']);
    }

    public function testNothingIsSentTwice(): void
    {
        $this->store->insert(Findings::make(advisory: 'PKSA-1'));
        $this->transport->expects($this->once())->method('sendMessage');
        $notifier = $this->notifier();

        $this->assertSame(1, $notifier->notifyPending());
        $this->assertSame(0, $notifier->notifyPending());
    }

    public function testAFindingThatBecomesExploitedIsSentAgain(): void
    {
        $this->store->insert(Findings::make(advisory: 'PKSA-1'));
        $this->transport->expects($this->exactly(2))->method('sendMessage');
        $notifier = $this->notifier();
        $notifier->notifyPending();

        $this->store->update(Findings::make(advisory: 'PKSA-1', exploited: true), true);

        $this->assertSame(1, $notifier->notifyPending());
        $this->assertSame(1, $this->vars['exploited_count']);
    }

    public function testBelowTheMinimumSeverityIsNotSentButIsNotRetried(): void
    {
        $this->store->insert(Findings::make(advisory: 'PKSA-1', severity: 'low'));
        $this->transport->expects($this->never())->method('sendMessage');
        $notifier = $this->notifier();

        $this->assertSame(0, $notifier->notifyPending());
        $this->assertSame([], $this->store->pendingNotification());
    }

    public function testExploitedIgnoresTheMinimumSeverity(): void
    {
        $this->store->insert(Findings::make(advisory: 'PKSA-1', exploited: true, severity: 'low'));
        $this->transport->expects($this->once())->method('sendMessage');

        $this->assertSame(1, $this->notifier()->notifyPending());
    }

    public function testUnratedCountsAsHighForTheMinimum(): void
    {
        $this->store->insert(Findings::make(advisory: 'PKSA-1', severity: null));
        $this->transport->expects($this->once())->method('sendMessage');

        $this->assertSame(1, $this->notifier()->notifyPending());
        $this->assertStringContainsString('not rated', $this->vars['other_block']);
    }

    public function testDismissedFindingsAreNotSent(): void
    {
        $this->store->insert(Findings::make(advisory: 'PKSA-1', exploited: true));
        $this->store->dismiss(1);
        $this->transport->expects($this->never())->method('sendMessage');

        $this->assertSame(0, $this->notifier()->notifyPending());
    }

    public function testDisabledOrWithoutRecipientsKeepsFindingsPending(): void
    {
        $this->store->insert(Findings::make(advisory: 'PKSA-1', exploited: true));
        $config = $this->createMock(Config::class);
        $config->method('isEnabled')->willReturn(true);
        $config->method('recipients')->willReturn([]);
        $this->transport->expects($this->never())->method('sendMessage');

        $notifier = new Notifier(
            $config,
            $this->store,
            $this->builder,
            Escapers::make(),
            $this->createMock(LoggerInterface::class)
        );

        $this->assertSame(0, $notifier->notifyPending());
        $this->assertCount(1, $this->store->pendingNotification());
    }

    public function testAFailedSendKeepsFindingsPendingAndIsLogged(): void
    {
        $this->store->insert(Findings::make(advisory: 'PKSA-1', exploited: true));
        $this->transport->method('sendMessage')->willThrowException(new \RuntimeException('SMTP down'));
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())->method('error')->with($this->stringContains('SMTP down'));

        $notifier = new Notifier($this->config, $this->store, $this->builder, Escapers::make(), $logger);

        $this->assertSame(0, $notifier->notifyPending());
        $this->assertCount(1, $this->store->pendingNotification());
    }

    public function testAdvisoryTextIsEscapedAndOnlyHttpLinksAreLinked(): void
    {
        $this->store->insert(Findings::make(advisory: 'PKSA-1', title: '<script>alert(1)</script> & more'));
        $this->store->insert(new \Ruvelo\SecurityAlerts\Model\Finding(
            'acme/x',
            '1.0',
            'PKSA-2',
            'Bad link',
            'javascript:alert(1)',
            null,
            'high',
            null
        ));

        $this->notifier()->notifyPending();

        $block = $this->vars['other_block'];
        $this->assertStringNotContainsString('<script>', $block);
        $this->assertStringContainsString('&lt;script&gt;', $block);
        $this->assertStringNotContainsString('javascript:', $block);
        $this->assertStringContainsString('<a href="https://example.com/PKSA-1">', $block);
        $this->assertStringContainsString('no fixed version listed', $block);
    }

    public function testSubjectWithoutExploitedItems(): void
    {
        $this->store->insert(Findings::make(advisory: 'PKSA-1'));

        $this->notifier()->notifyPending();

        $this->assertSame('1 new security advisory for your Magento store', $this->vars['subject']);
    }
}
