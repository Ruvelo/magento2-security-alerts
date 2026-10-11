<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit;

use PHPUnit\Framework\TestCase;
use SimpleXMLElement;

/**
 * Without a booted Magento nothing reads the XML, so a typo would only show up on a real store.
 * These tests cross-check the files against each other and against the classes.
 */
class ModuleWiringTest extends TestCase
{
    private const ROOT = __DIR__ . '/../..';

    private function xml(string $path): SimpleXMLElement
    {
        $xml = simplexml_load_file(self::ROOT . '/' . $path);
        $this->assertInstanceOf(SimpleXMLElement::class, $xml, $path . ' is not well-formed XML');

        return $xml;
    }

    /**
     * @return list<string>
     */
    private function aclIds(): array
    {
        return array_map(
            static fn (SimpleXMLElement $r): string => (string)$r['id'],
            $this->xml('etc/acl.xml')->xpath('//resource[@title]') ?: []
        );
    }

    public function testTheDatabaseWhitelistCoversTheSchema(): void
    {
        $schema = $this->xml('etc/db_schema.xml');
        $whitelist = json_decode((string)file_get_contents(self::ROOT . '/etc/db_schema_whitelist.json'), true);

        foreach ($schema->table as $table) {
            $name = (string)$table['name'];
            $this->assertArrayHasKey($name, $whitelist);
            foreach ($table->column as $column) {
                $this->assertArrayHasKey((string)$column['name'], $whitelist[$name]['column'], 'column ' . $column['name']);
            }
            foreach ($table->index as $index) {
                $this->assertArrayHasKey((string)$index['referenceId'], $whitelist[$name]['index']);
            }
            foreach ($table->constraint as $constraint) {
                $this->assertArrayHasKey((string)$constraint['referenceId'], $whitelist[$name]['constraint']);
            }
        }
    }

    public function testAclResourcesUsedElsewhereExist(): void
    {
        $acl = $this->aclIds();
        $this->assertContains('Ruvelo_SecurityAlerts::alerts', $acl);
        $this->assertContains('Ruvelo_SecurityAlerts::config', $acl);

        $menu = $this->xml('etc/adminhtml/menu.xml')->xpath('//add/@resource') ?: [];
        foreach ($menu as $resource) {
            $this->assertContains((string)$resource, [...$acl, 'Magento_Backend::tools']);
        }
        $this->assertSame('Ruvelo_SecurityAlerts::config', (string)$this->xml('etc/adminhtml/system.xml')->system->section->resource);

        foreach (glob(self::ROOT . '/Controller/Adminhtml/Alerts/*.php') ?: [] as $file) {
            $this->assertStringContainsString("ADMIN_RESOURCE = 'Ruvelo_SecurityAlerts::alerts'", (string)file_get_contents($file));
        }
    }

    public function testEveryClassNamedInXmlExists(): void
    {
        $files = array_merge(
            glob(self::ROOT . '/etc/*.xml') ?: [],
            glob(self::ROOT . '/etc/adminhtml/*.xml') ?: [],
            glob(self::ROOT . '/view/adminhtml/layout/*.xml') ?: []
        );
        $checked = 0;
        foreach ($files as $file) {
            $contents = (string)file_get_contents($file);
            preg_match_all('/Ruvelo\\\\SecurityAlerts\\\\[A-Za-z\\\\]+/', $contents, $matches);
            foreach (array_unique($matches[0]) as $class) {
                $this->assertTrue(
                    class_exists($class) || interface_exists($class) || enum_exists($class),
                    basename($file) . ' names a class that does not exist: ' . $class
                );
                $checked++;
            }
        }
        $this->assertGreaterThan(8, $checked);
    }

    public function testCronJobPointsAtAnExecuteMethod(): void
    {
        $job = $this->xml('etc/crontab.xml')->group->job;

        $this->assertSame('default', (string)$this->xml('etc/crontab.xml')->group['id']);
        $this->assertTrue(method_exists((string)$job['instance'], (string)$job['method']));
        $this->assertNotSame('', (string)$job->schedule);
    }

    public function testTheEmailTemplateExistsAndUsesTheVariablesTheNotifierSends(): void
    {
        $template = $this->xml('etc/email_templates.xml')->template;
        $file = self::ROOT . '/view/adminhtml/email/' . $template['file'];

        $this->assertSame('ruvelo_security_alerts_email_template', (string)$template['id']);
        $this->assertSame(\Ruvelo\SecurityAlerts\Model\Notifier::TEMPLATE_ID, (string)$template['id']);
        $contents = (string)file_get_contents($file);
        foreach (['subject', 'exploited_block|raw', 'other_block|raw', 'depend has_exploited', 'depend has_other'] as $var) {
            $this->assertStringContainsString($var, $contents);
        }
    }

    public function testTheSystemMessageIsRegisteredOnce(): void
    {
        $items = $this->xml('etc/adminhtml/di.xml')->xpath('//argument[@name="messages"]/item') ?: [];

        $this->assertCount(1, $items);
        $this->assertSame(\Ruvelo\SecurityAlerts\Model\System\ExploitedMessage::class, (string)$items[0]);
    }

    public function testConfigPathsMatchTheSystemXmlAndDefaults(): void
    {
        $fields = array_map(
            static fn (SimpleXMLElement $f): string => (string)$f['id'],
            $this->xml('etc/adminhtml/system.xml')->xpath('//group/field') ?: []
        );
        $defaults = array_keys((array)$this->xml('etc/config.xml')->default->ruvelo_security_alerts->general);

        $this->assertSame(['enabled', 'emails', 'min_severity'], $fields);
        $this->assertSame($fields, $defaults);
        $this->assertSame('ruvelo_security_alerts/general/enabled', \Ruvelo\SecurityAlerts\Model\Config::XML_ENABLED);
        $this->assertSame('advanced', (string)$this->xml('etc/adminhtml/system.xml')->system->section->tab);
    }

    public function testNothingInTheModuleMentionsValtry(): void
    {
        $dirs = ['Block', 'Console', 'Controller', 'Cron', 'Model', 'etc', 'view', 'Exception'];
        foreach ($dirs as $dir) {
            $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(self::ROOT . '/' . $dir));
            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $this->assertStringNotContainsStringIgnoringCase('valtry', (string)file_get_contents($file->getPathname()));
                }
            }
        }
    }
}
