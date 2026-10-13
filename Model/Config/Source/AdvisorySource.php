<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Model\Config\Source;

use Magento\Framework\Data\OptionSourceInterface;
use Ruvelo\SecurityAlerts\Model\Config;

class AdvisorySource implements OptionSourceInterface
{
    /**
     * To option array.
     *
     * @return list<array{value: string, label: \Magento\Framework\Phrase}>
     */
    public function toOptionArray(): array
    {
        return [
            ['value' => Config::SOURCE_VALTRY, 'label' => __('Valtry (default)')],
            ['value' => Config::SOURCE_PUBLIC, 'label' => __('Public feeds only')],
        ];
    }
}
