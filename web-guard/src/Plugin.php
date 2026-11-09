<?php

namespace Botble\WebGuard;

use Botble\PluginManagement\Abstracts\PluginOperationAbstract;

class Plugin extends PluginOperationAbstract
{
    public static function remove(): void
    {
        // Keep audit/history. The independent root engine is managed by its CLI.
    }
}
