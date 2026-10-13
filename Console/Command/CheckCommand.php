<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Console\Command;

use Magento\Framework\App\State;
use Magento\Framework\Console\Cli;
use Ruvelo\SecurityAlerts\Exception\SourceException;
use Ruvelo\SecurityAlerts\Model\Checker;
use Ruvelo\SecurityAlerts\Model\Finding;
use Ruvelo\SecurityAlerts\Model\ScanResult;
use Ruvelo\SecurityAlerts\Model\Scanner;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class CheckCommand extends Command
{
    public const EXIT_FINDINGS = 1;
    public const EXIT_ERROR = 2;

    /**
     * __construct.
     *
     * @param Checker $checker
     * @param Scanner $scanner
     * @param State $state
     */
    public function __construct(
        private readonly Checker $checker,
        private readonly Scanner $scanner,
        private readonly State $state
    ) {
        parent::__construct();
    }

    /**
     * @inheritdoc
     */
    protected function configure(): void
    {
        $this->setName('ruvelo:security-alerts:check')
            ->setDescription('Check this store for known vulnerabilities in Magento and installed extensions')
            ->addOption('json', null, InputOption::VALUE_NONE, 'Print the findings as JSON')
            ->addOption(
                'fail-on',
                null,
                InputOption::VALUE_REQUIRED,
                'Exit with code 1 when there are findings: "exploited" (known to be exploited) or "any"'
            )
            ->addOption(
                'dry-run',
                null,
                InputOption::VALUE_NONE,
                'Only report: do not update the stored findings, send email or dispatch the event'
            );
    }

    /**
     * @inheritdoc
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $failOn = $input->getOption('fail-on');
        if ($failOn !== null && !in_array($failOn, ['exploited', 'any'], true)) {
            $output->writeln('<error>--fail-on must be "exploited" or "any".</error>');

            return self::EXIT_ERROR;
        }

        try {
            $this->state->emulateAreaCode('adminhtml', function () use ($input, &$result): void {
                $result = $input->getOption('dry-run')
                    ? $this->scanner->scan()
                    : $this->checker->run()->result;
            });
        } catch (SourceException $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');

            return self::EXIT_ERROR;
        }
        /** @var ScanResult $result */

        if ($input->getOption('json')) {
            $output->writeln((string)json_encode([
                'exploited' => count($result->exploited()),
                'total' => count($result->findings),
                'packages_checked' => $result->packagesChecked,
                'source' => $result->source,
                'warnings' => $result->warnings,
                'findings' => array_map(static fn (Finding $f): array => $f->toArray(), $result->findings),
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        } else {
            $this->printText($result, $output);
        }

        $failed = ($failOn === 'any' && $result->findings !== [])
            || ($failOn === 'exploited' && $result->exploited() !== []);

        return $failed ? self::EXIT_FINDINGS : Cli::RETURN_SUCCESS;
    }

    /**
     * Print text.
     *
     * @param ScanResult $result
     * @param OutputInterface $output
     * @return void
     */
    private function printText(ScanResult $result, OutputInterface $output): void
    {
        foreach ($result->warnings as $warning) {
            $output->writeln('<comment>Warning: ' . $warning . '</comment>');
        }
        if ($result->findings === []) {
            $output->writeln(sprintf('No known vulnerabilities found in %d packages.', $result->packagesChecked));
            $output->writeln(sprintf('Data source: %s.', $result->sourceLabel()));

            return;
        }

        foreach ($result->findings as $f) {
            $output->writeln(sprintf(
                '%s %s %s: %s',
                $f->exploited ? '<error>EXPLOITED — PATCH NOW</error>' : strtoupper($f->severityLevel()->value),
                $f->package,
                $f->installedVersion,
                $f->title
            ));
            $output->writeln(sprintf(
                '    %s | fixed in %s | %s',
                $f->cve ?? 'no CVE',
                $f->fixedIn ?? 'no fixed version listed',
                $f->link ?? 'no link'
            ));
        }
        $output->writeln(sprintf(
            "\n%d findings, %d exploited, in %d packages checked.",
            count($result->findings),
            count($result->exploited()),
            $result->packagesChecked
        ));
        $output->writeln(sprintf('Data source: %s.', $result->sourceLabel()));
    }
}
