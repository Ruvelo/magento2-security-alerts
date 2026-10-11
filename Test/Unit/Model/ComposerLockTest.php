<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Model;

use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\Exception\FileSystemException;
use Magento\Framework\Filesystem\Driver\File;
use Magento\Framework\Phrase;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlerts\Exception\SourceException;
use Ruvelo\SecurityAlerts\Model\ComposerLock;

class ComposerLockTest extends TestCase
{
    private function lock(?string $contents, bool $exists = true): ComposerLock
    {
        $directories = $this->createMock(DirectoryList::class);
        $directories->method('getRoot')->willReturn('/var/www/magento');
        $file = $this->createMock(File::class);
        $file->method('isExists')->with('/var/www/magento/composer.lock')->willReturn($exists);
        $file->method('fileGetContents')->willReturn((string)$contents);

        return new ComposerLock($directories, $file);
    }

    public function testReadsExactVersionsAndSkipsTheBundledModules(): void
    {
        $json = json_encode(['packages' => [
            ['name' => 'acme/module-widgets', 'version' => '1.2.0'],
            ['name' => 'amasty/base', 'version' => '1.20.3'],
            ['name' => 'magento/module-catalog', 'version' => '104.0.7'],
            ['name' => 'magento/theme-frontend-luma', 'version' => '100.4.7'],
            ['name' => 'magento/language-en_us', 'version' => '100.4.0'],
            ['name' => 'mage-os/module-cms', 'version' => '2.0.0'],
            ['name' => 'magento/framework', 'version' => '103.0.7'],
            ['name' => 'broken'],
        ], 'packages-dev' => [['name' => 'phpunit/phpunit', 'version' => '10.0.0']]]);

        $this->assertSame(
            ['acme/module-widgets' => '1.2.0', 'amasty/base' => '1.20.3', 'magento/framework' => '103.0.7'],
            $this->lock((string)$json)->packages()
        );
    }

    public function testMissingFileIsASourceError(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('composer.lock was not found');
        $this->lock(null, false)->packages();
    }

    public function testInvalidJsonIsASourceError(): void
    {
        $this->expectException(SourceException::class);
        $this->lock('{nope')->packages();
    }

    public function testUnreadableFileIsASourceError(): void
    {
        $directories = $this->createMock(DirectoryList::class);
        $directories->method('getRoot')->willReturn('/x');
        $file = $this->createMock(File::class);
        $file->method('isExists')->willReturn(true);
        $file->method('fileGetContents')->willThrowException(new FileSystemException(new Phrase('denied')));

        $this->expectException(SourceException::class);
        (new ComposerLock($directories, $file))->packages();
    }
}
