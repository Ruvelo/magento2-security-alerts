<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Console;

use Magento\Framework\App\State;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Console\Command\CheckCommand;
use Ruvelo\SecurityAlerts\Exception\SourceException;
use Ruvelo\SecurityAlerts\Model\Changes;
use Ruvelo\SecurityAlerts\Model\CheckOutcome;
use Ruvelo\SecurityAlerts\Model\Checker;
use Ruvelo\SecurityAlerts\Model\Finding;
use Ruvelo\SecurityAlerts\Model\ScanResult;
use Ruvelo\SecurityAlerts\Model\Scanner;
use Ruvelo\SecurityAlerts\Test\Unit\Fake\Findings;
use Symfony\Component\Console\Tester\CommandTester;

class CheckCommandTest extends TestCase
{
    /**
     * @param list<Finding> $findings
     * @param list<string> $warnings
     * @return array{CommandTester, Checker&MockObject, Scanner&MockObject}
     */
    private function tester(array $findings, ?SourceException $error = null, array $warnings = [], string $source = 'valtry'): array
    {
        $result = new ScanResult($findings, $warnings, 42, $source);
        $checker = $this->createMock(Checker::class);
        $scanner = $this->createMock(Scanner::class);
        if ($error !== null) {
            $checker->method('run')->willThrowException($error);
            $scanner->method('scan')->willThrowException($error);
        } else {
            $checker->method('run')->willReturn(new CheckOutcome($result, new Changes([], [], 0), 0));
            $scanner->method('scan')->willReturn($result);
        }
        $state = $this->createMock(State::class);
        $state->method('emulateAreaCode')->willReturnCallback(static fn (string $area, callable $fn): mixed => $fn());

        return [new CommandTester(new CheckCommand($checker, $scanner, $state)), $checker, $scanner];
    }

    public function testCleanStoreExitsZeroEvenWithFailOnAny(): void
    {
        [$tester] = $this->tester([]);

        $code = $tester->execute(['--fail-on' => 'any']);

        $this->assertSame(0, $code);
        $this->assertStringContainsString('No known vulnerabilities found in 42 packages.', $tester->getDisplay());
    }

    public function testFailOnExploitedIgnoresOtherFindings(): void
    {
        [$tester] = $this->tester([Findings::make()]);

        $this->assertSame(0, $tester->execute(['--fail-on' => 'exploited']));
    }

    public function testFailOnExploitedFailsOnAnExploitedFinding(): void
    {
        [$tester] = $this->tester([Findings::make(exploited: true)]);

        $this->assertSame(1, $tester->execute(['--fail-on' => 'exploited']));
        $this->assertStringContainsString('EXPLOITED', $tester->getDisplay());
    }

    public function testFailOnAnyFailsOnAnyFinding(): void
    {
        [$tester] = $this->tester([Findings::make()]);

        $this->assertSame(1, $tester->execute(['--fail-on' => 'any']));
    }

    public function testWithoutFailOnFindingsDoNotChangeTheExitCode(): void
    {
        [$tester] = $this->tester([Findings::make(exploited: true)]);

        $this->assertSame(0, $tester->execute([]));
    }

    public function testRejectsAnUnknownFailOn(): void
    {
        [$tester, $checker] = $this->tester([]);
        $checker->expects($this->never())->method('run');

        $this->assertSame(2, $tester->execute(['--fail-on' => 'high']));
        $this->assertStringContainsString('"exploited" or "any"', $tester->getDisplay());
    }

    public function testJsonOutputIsMachineReadable(): void
    {
        [$tester] = $this->tester(
            [Findings::make(exploited: true, title: 'Remote code execution'), Findings::make(advisory: 'PKSA-2', severity: null)],
            null,
            ['CISA was slow']
        );

        $code = $tester->execute(['--json' => true, '--fail-on' => 'exploited']);

        $this->assertSame(1, $code);
        $data = json_decode($tester->getDisplay(), true, 512, JSON_THROW_ON_ERROR);
        $this->assertSame(1, $data['exploited']);
        $this->assertSame(2, $data['total']);
        $this->assertSame(42, $data['packages_checked']);
        $this->assertSame(['CISA was slow'], $data['warnings']);
        $this->assertSame('Remote code execution', $data['findings'][0]['title']);
        $this->assertTrue($data['findings'][0]['exploited']);
        $this->assertNull($data['findings'][1]['severity']);
        $this->assertSame('high', $data['findings'][1]['severity_level']);
    }

    public function testTheSummaryNamesTheDataSource(): void
    {
        [$clean] = $this->tester([], null, [], 'valtry');
        [$found] = $this->tester([Findings::make()], null, [], 'public');

        $clean->execute([]);
        $found->execute([]);

        $this->assertStringContainsString('Data source: Valtry Advisory API.', $clean->getDisplay());
        $this->assertStringContainsString('Data source: Public feeds (Packagist, CISA).', $found->getDisplay());
    }

    public function testJsonSaysWhichSourceAnswered(): void
    {
        [$tester] = $this->tester([], null, [], 'mixed');

        $tester->execute(['--json' => true]);

        $this->assertSame('mixed', json_decode($tester->getDisplay(), true, 512, JSON_THROW_ON_ERROR)['source']);
    }

    public function testDryRunOnlyScans(): void
    {
        [$tester, $checker, $scanner] = $this->tester([Findings::make()]);
        $checker->expects($this->never())->method('run');
        $scanner->expects($this->once())->method('scan');

        $tester->execute(['--dry-run' => true]);
    }

    public function testASourceFailureExitsTwo(): void
    {
        [$tester] = $this->tester([], new SourceException('Packagist is down.'));

        $this->assertSame(2, $tester->execute(['--fail-on' => 'any']));
        $this->assertStringContainsString('Packagist is down.', $tester->getDisplay());
    }

    public function testWarningsAreShown(): void
    {
        [$tester] = $this->tester([], null, ['composer.lock was not found']);

        $tester->execute([]);

        $this->assertStringContainsString('Warning: composer.lock was not found', $tester->getDisplay());
    }

    public function testCommandName(): void
    {
        $command = new CheckCommand(
            $this->createMock(Checker::class),
            $this->createMock(Scanner::class),
            $this->createMock(State::class)
        );

        $this->assertSame('ruvelo:security-alerts:check', $command->getName());
        $this->assertTrue($command->getDefinition()->hasOption('json'));
        $this->assertTrue($command->getDefinition()->hasOption('fail-on'));
    }
}
