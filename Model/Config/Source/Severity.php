<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model\Config\Source;

use Magento\Framework\Data\OptionSourceInterface;
use Ruvelo\SecurityAlerts\Model\Severity as SeverityLevel;

class Severity implements OptionSourceInterface
{
    /**
     * To option array.
     *
     * @return list<array{value: string, label: \Magento\Framework\Phrase}>
     */
    public function toOptionArray(): array
    {
        $options = [];
        foreach (SeverityLevel::cases() as $case) {
            $options[] = ['value' => $case->value, 'label' => __($case->label())];
        }

        return $options;
    }
}
