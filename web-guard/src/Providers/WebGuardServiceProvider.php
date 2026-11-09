<?php

namespace Botble\WebGuard\Providers;

use Botble\Base\Facades\DashboardMenu;
use Botble\Base\Supports\DashboardMenuItem;
use Botble\Base\Supports\ServiceProvider;
use Botble\Base\Traits\LoadAndPublishDataTrait;
use Botble\WebGuard\Commands\SelfTestCommand;
use Botble\WebGuard\Commands\PruneCommand;

class WebGuardServiceProvider extends ServiceProvider
{
    use LoadAndPublishDataTrait;

    public function boot(): void
    {
        $this->setNamespace('plugins/web-guard')->loadAndPublishConfigurations(['permissions', 'general'])
            ->loadRoutes()->loadAndPublishTranslations()->loadAndPublishViews()->loadMigrations()->publishAssets();
        // Every view gets $t('key', ['name' => 'value']): the text in the admin's language (English or Albanian).
        view()->composer('plugins/web-guard::*', function ($view): void {
            $view->with('t', static fn (string $key, array $replace = []): string => (string) trans('plugins/web-guard::web-guard.' . $key, $replace));
        });
        if ($this->app->runningInConsole()) {
            $this->commands([SelfTestCommand::class, PruneCommand::class]);
            $this->callAfterResolving(\Illuminate\Console\Scheduling\Schedule::class, function ($schedule): void {
                $schedule->command('web-guard:prune')->dailyAt('03:20')->withoutOverlapping();
            });
        }
        DashboardMenu::default()->beforeRetrieving(function (): void {
            $menu = DashboardMenu::make();
            $menu->registerItem(DashboardMenuItem::make()->id('cms-plugins-web-guard')->priority(125)
                ->name('Web Guard')->icon('ti ti-shield-lock')->permissions([
                    'web-guard.dashboard', 'web-guard.incidents', 'web-guard.bans', 'web-guard.settings', 'web-guard.allowlist', 'web-guard.paths', 'web-guard.audit', 'web-guard.setup',
                ]));
            foreach (['dashboard', 'incidents', 'bans', 'allowlist', 'paths', 'settings', 'audit', 'setup'] as $key) {
                $label = 'plugins/web-guard::web-guard.nav_' . $key;
                $menu->registerItem(DashboardMenuItem::make()->id('cms-web-guard-' . $key)->parentId('cms-plugins-web-guard')
                    ->priority(10)->name($label)->route('web-guard.' . $key)->permissions('web-guard.' . $key));
            }
        });
    }
}
