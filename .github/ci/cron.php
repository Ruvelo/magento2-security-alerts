<?php
/**
 * CI only. Runs the cron job class the way cron does (area "crontab") and prints the row count.
 * Run from the Magento root: php /path/to/cron.php
 */
declare(strict_types=1);

use Magento\Cron\Model\ConfigInterface as CronConfig;
use Magento\Framework\App\Bootstrap;
use Magento\Framework\App\ResourceConnection;
use Magento\Framework\App\State;
use Ruvelo\SecurityAlerts\Cron\DailyCheck;

require getcwd() . '/app/bootstrap.php';

$om = Bootstrap::create(BP, $_SERVER)->getObjectManager();
$om->get(State::class)->setAreaCode('crontab');

$jobs = $om->get(CronConfig::class)->getJobs();
$job = $jobs['default']['ruvelo_security_alerts_daily_check'] ?? null;
if ($job === null || ltrim((string)$job['instance'], '\\') !== DailyCheck::class || $job['method'] !== 'execute') {
    fwrite(STDERR, "FAIL: ruvelo_security_alerts_daily_check is not registered in the default cron group\n");
    exit(1);
}
echo "cron job registered: {$job['instance']}::{$job['method']} at {$job['schedule']}\n";

$om->get(DailyCheck::class)->execute();

$resource = $om->get(ResourceConnection::class);
$count = (int)$resource->getConnection()->fetchOne(
    'SELECT COUNT(*) FROM ' . $resource->getTableName('ruvelo_security_alerts_finding')
);
echo "rows after cron job: $count\n";
