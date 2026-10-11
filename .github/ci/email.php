<?php
/**
 * CI only. Stores one made-up exploited finding, renders the real email template with the real Notifier,
 * checks the {{depend}} blocks and the raw HTML, and runs the notification path end to end.
 * Mail sending is disabled by the workflow (system/smtp/disable), so nothing leaves the machine.
 * Run from the Magento root.
 */
declare(strict_types=1);

use Magento\Framework\App\Bootstrap;
use Magento\Framework\App\ResourceConnection;
use Magento\Framework\App\State;
use Magento\Framework\Mail\Template\FactoryInterface;
use Ruvelo\SecurityAlerts\Model\Finding;
use Ruvelo\SecurityAlerts\Model\FindingRepository;
use Ruvelo\SecurityAlerts\Model\Notifier;

require getcwd() . '/app/bootstrap.php';

$fail = static function (string $message): never {
    fwrite(STDERR, "FAIL: $message\n");
    exit(1);
};

$om = Bootstrap::create(BP, $_SERVER)->getObjectManager();
$om->get(State::class)->emulateAreaCode('adminhtml', static function () use ($om, $fail): void {
    // 1. The template on its own: both {{depend}} branches, and the pre-escaped HTML printed with |raw.
    $render = static function (array $vars) use ($om): string {
        $template = $om->get(FactoryInterface::class)->get(Notifier::TEMPLATE_ID);
        $template->setOptions(['area' => 'adminhtml', 'store' => 0]);
        $template->setVars($vars);

        return $template->processTemplate();
    };
    $both = $render([
        'subject' => 'x', 'has_exploited' => '1', 'has_other' => '1', 'exploited_count' => 1, 'other_count' => 1,
        'exploited_block' => '<p id="raw-exploited"><a href="https://example.com/?a=1&amp;b=2">Bad</a></p>',
        'other_block' => '<p id="raw-other">Meh</p>',
    ]);
    foreach (['Exploited — patch now', 'Other new findings', '<p id="raw-exploited">', '<p id="raw-other">', '&amp;b=2'] as $needle) {
        if (!str_contains($both, $needle)) {
            $fail("rendered email lacks: $needle");
        }
    }
    $onlyOthers = $render([
        'subject' => 'x', 'has_exploited' => '', 'has_other' => '1', 'exploited_count' => 0, 'other_count' => 1, 'exploited_block' => '', 'other_block' => '<p>Meh</p>',
    ]);
    if (str_contains($onlyOthers, 'Exploited — patch now') || !str_contains($onlyOthers, 'Other new findings')) {
        $fail('{{depend}} did not hide the exploited section when exploited_count is 0');
    }
    if (preg_match('/\{\{|\}\}/', $both . $onlyOthers) === 1) {
        $fail('unprocessed template directives left in the email');
    }
    echo "email template renders\n";

    // 2. The whole path: repository insert, pendingNotification, Notifier, markNotified.
    $repository = $om->get(FindingRepository::class);
    $repository->insert(new Finding(
        'acme/ci-fake', '1.0.0', 'CI-FAKE-1', 'Fake <b>exploited</b> finding', 'https://example.com/a?b=1&c=2',
        'CVE-2099-0001', 'high', '1.0.1', true
    ));
    if ($repository->openExploitedIds() === []) {
        $fail('the stored exploited finding is not returned by openExploitedIds()');
    }
    if (count($repository->pendingNotification()) < 1) {
        $fail('the stored finding is not pending');
    }
    $sent = $om->get(Notifier::class)->notifyPending();
    if ($sent < 1) {
        $fail('Notifier sent nothing (are notification emails configured?)');
    }
    if ($repository->pendingNotification() !== []) {
        $fail('findings are still pending after notifying');
    }
    $row = current(array_filter($repository->all(), static fn (Finding $f): bool => $f->advisoryId === 'CI-FAKE-1'));
    $repository->dismiss((int)$row->id);
    if (in_array((int)$row->id, $repository->openExploitedIds(), true)) {
        $fail('a dismissed finding is still open');
    }
    $repository->delete((int)$row->id);
    echo "notification path ok ($sent finding(s) emailed)\n";
});
