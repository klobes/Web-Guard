<?php

use Botble\Base\Facades\AdminHelper;
use Botble\WebGuard\Http\Controllers\AgentController;
use Botble\WebGuard\Http\Controllers\WebGuardController;
use Botble\WebGuard\Http\Middleware\AuthenticateAgent;
use Illuminate\Support\Facades\Route;

AdminHelper::registerRoutes(function (): void {
    Route::group(['prefix' => 'web-guard', 'as' => 'web-guard.'], function (): void {
        foreach (['dashboard', 'incidents', 'bans', 'allowlist', 'paths', 'settings', 'audit', 'setup'] as $page) {
            Route::get($page === 'dashboard' ? '/' : $page, [
                'uses' => WebGuardController::class . '@' . $page, 'as' => $page, 'permission' => 'web-guard.' . $page,
            ]);
        }
        Route::get('metrics', ['uses' => WebGuardController::class . '@metrics', 'as' => 'metrics', 'permission' => 'web-guard.dashboard']);
        Route::post('settings', ['uses' => WebGuardController::class . '@saveSettings', 'as' => 'settings.save', 'permission' => 'web-guard.settings.edit']);
        Route::post('rules', ['uses' => WebGuardController::class . '@saveRules', 'as' => 'rules.save', 'permission' => 'web-guard.settings.edit']);
        Route::post('lockdown', ['uses' => WebGuardController::class . '@saveLockdown', 'as' => 'lockdown.save', 'permission' => 'web-guard.settings.edit']);
        Route::post('allowlist', ['uses' => WebGuardController::class . '@addAllowlist', 'as' => 'allowlist.add', 'permission' => 'web-guard.allowlist.edit']);
        Route::delete('allowlist/{id}', ['uses' => WebGuardController::class . '@deleteAllowlist', 'as' => 'allowlist.delete', 'permission' => 'web-guard.allowlist.edit'])->whereNumber('id');
        Route::post('paths', ['uses' => WebGuardController::class . '@addPath', 'as' => 'paths.add', 'permission' => 'web-guard.paths.edit']);
        Route::post('paths/{id}/toggle', ['uses' => WebGuardController::class . '@togglePath', 'as' => 'paths.toggle', 'permission' => 'web-guard.paths.edit'])->whereNumber('id');
        Route::delete('paths/{id}', ['uses' => WebGuardController::class . '@deletePath', 'as' => 'paths.delete', 'permission' => 'web-guard.paths.edit'])->whereNumber('id');
        Route::post('bans/{id}/unban', ['uses' => WebGuardController::class . '@unban', 'as' => 'bans.unban', 'permission' => 'web-guard.unban'])->whereNumber('id');
    });
});

// This route has its own HMAC + loopback middleware. It does not use browser sessions.
Route::post('web-guard-agent/sync', [AgentController::class, 'sync'])
    ->middleware(AuthenticateAgent::class)->name('web-guard.agent.sync');
