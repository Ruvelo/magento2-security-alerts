<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Test\Unit\Fake;

use Magento\Framework\Escaper;
use Magento\Framework\Translate\InlineInterface;
use Magento\Framework\ZendEscaper;
use ReflectionProperty;

class Escapers
{
    /**
     * The real Escaper. Outside a booted Magento it cannot find its collaborators through the
     * ObjectManager, so it is handed them.
     */
    public static function make(): Escaper
    {
        $escaper = new Escaper();
        (new ReflectionProperty(Escaper::class, 'escaper'))->setValue($escaper, new ZendEscaper());
        (new ReflectionProperty(Escaper::class, 'translateInline'))->setValue(
            $escaper,
            new class implements InlineInterface {
                public function getAdditionalHtmlAttribute($tagName = null)
                {
                    return '';
                }

                public function isAllowed()
                {
                    return false;
                }

                /**
                 * @param string|array<mixed> $body
                 */
                public function processResponseBody(&$body, $isJson = false)
                {
                    return $this;
                }

                public function getParser()
                {
                    throw new \LogicException('Not used by the Escaper.');
                }
            }
        );

        return $escaper;
    }
}
