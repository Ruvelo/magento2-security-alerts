<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Model;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Model\AdvisoryMatcher;

class AdvisoryMatcherTest extends TestCase
{
    /** CVE-2024-34102, "CosmicSting", as Packagist lists it. */
    private const COSMICSTING = '<2.4.4|>=2.4.4,<2.4.4-p9|>=2.4.5,<2.4.5-p8|>=2.4.6,<2.4.6-p6|>=2.4.7,<2.4.7-p1';

    /** CVE-2025-54264, which also lists bare releases with "=". */
    private const WITH_EXACT = '=2.4.6|=2.4.7|=2.4.8|<2.4.6-p13|>=2.4.7-beta1,<2.4.7-p8|>=2.4.8-beta1,<2.4.8-p3'
        . '|>=2.4.9-alpha1,<2.4.9-alpha3';

    /**
     * @return array<string, array{string, string, bool}>
     */
    public static function affected(): array
    {
        return [
            'before the first patch line' => ['2.4.7', self::COSMICSTING, true],
            'patched 2.4.7' => ['2.4.7-p1', self::COSMICSTING, false],
            'later patch' => ['2.4.7-p3', self::COSMICSTING, false],
            'one patch short on 2.4.6' => ['2.4.6-p5', self::COSMICSTING, true],
            'fixed on 2.4.6' => ['2.4.6-p6', self::COSMICSTING, false],
            'old release' => ['2.3.7-p4', self::COSMICSTING, true],
            'the next minor' => ['2.4.8', self::COSMICSTING, false],
            'exact release listed' => ['2.4.8', self::WITH_EXACT, true],
            'patched past an exact release' => ['2.4.8-p3', self::WITH_EXACT, false],
            'a dev branch cannot be compared' => ['dev-main', self::COSMICSTING, false],
            'a v prefix is fine' => ['v1.2.0', '>=1.0.0,<1.4.2', true],
            'garbage constraint' => ['1.0.0', 'not a constraint !!', false],
        ];
    }

    #[DataProvider('affected')]
    public function testAffects(string $version, string $constraint, bool $expected): void
    {
        $this->assertSame($expected, (new AdvisoryMatcher())->affects($version, $constraint));
    }

    /**
     * @return array<string, array{string, string, string|null}>
     */
    public static function fixes(): array
    {
        return [
            'next patch on the same line' => ['2.4.7', self::COSMICSTING, '2.4.7-p1'],
            'follows the chain past a bare release' => ['2.4.3', self::COSMICSTING, '2.4.4-p9'],
            'a beta is fixed by the first patch' => ['2.4.7-beta1', self::WITH_EXACT, '2.4.7-p8'],
            'nothing to follow for an exact release' => ['2.4.7', '=2.4.7', null],
            'a third-party range' => ['1.2.0', '>=1.0.0,<1.4.2', '1.4.2'],
            'less-or-equal bound is not a fix version' => ['1.2.0', '<=1.4.2', null],
            'not affected at all' => ['3.0.0', '>=1.0.0,<1.4.2', null],
        ];
    }

    #[DataProvider('fixes')]
    public function testFixedIn(string $version, string $constraint, ?string $expected): void
    {
        $this->assertSame($expected, (new AdvisoryMatcher())->fixedIn($version, $constraint));
    }
}
