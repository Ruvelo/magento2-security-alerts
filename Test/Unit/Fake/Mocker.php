<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Fake;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * createMock() is protected on a TestCase; this lets a helper class use it.
 */
class Mocker
{
    /**
     * __construct.
     *
     * @param TestCase $test
     */
    public function __construct(private readonly TestCase $test)
    {
    }

    /**
     * Mock.
     *
     * @template T of object
     * @param class-string<T> $class
     * @return T&MockObject
     */
    public function mock(string $class): MockObject
    {
        return (fn () => $this->createMock($class))->call($this->test);
    }
}
