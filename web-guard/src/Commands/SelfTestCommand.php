<?php

namespace Botble\WebGuard\Commands;

use Botble\WebGuard\Http\Middleware\AuthenticateAgent;
use Botble\WebGuard\Services\SettingsService;
use Illuminate\Console\Command;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Symfony\Component\HttpKernel\Exception\HttpException;

class SelfTestCommand extends Command
{
    protected $signature = 'web-guard:self-test';
    protected $description = 'Verifikon tabelat, routes, CIDR dhe autentikimin lokal; pa bllokuar IP.';

    public function handle(): int
    {
        try {
            foreach (['configurations', 'agents', 'events', 'bans', 'allowlist', 'commands', 'audit', 'nonces'] as $table) {
                if (! Schema::hasTable('wg_' . $table)) {
                    throw new \RuntimeException('Tabela mungon: wg_' . $table);
                }
            }
            foreach (['dashboard', 'incidents', 'bans', 'allowlist', 'settings', 'audit', 'metrics', 'settings.save', 'allowlist.add', 'allowlist.delete', 'bans.unban'] as $name) {
                $route = Route::getRoutes()->getByName('web-guard.' . $name);
                if (! $route || ! str_starts_with((string) $route->getAction('permission'), 'web-guard.')) {
                    throw new \RuntimeException('Route/permission mungon: ' . $name);
                }
            }
            foreach (['127.0.0.1', '8.8.8.8/32', '2001:4860::/32'] as $ip) {
                if (! SettingsService::validNetwork($ip)) {
                    throw new \RuntimeException('CIDR i vlefshëm refuzohet');
                }
            }
            foreach (['example.com', '8.8.8.8/33', '::/129', '127.0.0.1/0/1'] as $ip) {
                if (SettingsService::validNetwork($ip)) {
                    throw new \RuntimeException('CIDR i pavlefshëm pranohet');
                }
            }
            foreach (glob(plugin_path('web-guard/resources/views/*.blade.php')) as $view) {
                $temporary = tempnam(sys_get_temp_dir(), 'wg-blade-');
                try {
                    file_put_contents($temporary, app('blade.compiler')->compileString(file_get_contents($view)));
                    $process = new \Symfony\Component\Process\Process([PHP_BINARY, '-l', $temporary]);
                    $process->mustRun();
                } finally {
                    @unlink($temporary);
                }
            }
            $path = config('plugins.web-guard.general.bridge_key_file');
            if (! is_readable($path)) {
                throw new \RuntimeException('Bridge key nuk lexohet nga përdoruesi i aplikacionit');
            }
            $key = trim(file_get_contents($path));
            $stamp = (string) time();
            $nonce = bin2hex(random_bytes(16));
            $body = '{"self_test":true}';
            $make = function (string $ip, string $signature) use ($stamp, $nonce, $body): Request {
                return Request::create('/web-guard-agent/sync', 'POST', [], [], [], [
                    'REMOTE_ADDR' => $ip, 'CONTENT_TYPE' => 'application/json', 'HTTP_X_WEBGUARD_TIME' => $stamp,
                    'HTTP_X_WEBGUARD_NONCE' => $nonce, 'HTTP_X_WEBGUARD_SIGNATURE' => $signature,
                ], $body);
            };
            $signature = hash_hmac('sha256', $stamp . "\n" . $nonce . "\n" . $body, $key);
            $middleware = new AuthenticateAgent();
            $deny = function (Request $request, int $status) use ($middleware): void {
                try {
                    $middleware->handle($request, fn () => response('PASS'));
                } catch (HttpException $error) {
                    if ($error->getStatusCode() === $status) {
                        return;
                    }
                    throw $error;
                }
                throw new \RuntimeException('Kërkesa e ndaluar u pranua');
            };
            try {
                $deny($make('8.8.8.8', $signature), 403);
                $deny($make('127.0.0.1', str_repeat('0', 64)), 403);
                $middleware->handle($make('127.0.0.1', $signature), fn () => response('PASS'));
                $deny($make('127.0.0.1', $signature), 409);
            } finally {
                DB::table('wg_nonces')->where('nonce', $nonce)->delete();
            }
            $this->info('BOTBLE_SELF_TEST=PASS tables=8 routes=11 CIDR=7 HMAC=4 Blade=7');
            return self::SUCCESS;
        } catch (\Throwable $error) {
            $this->error('BOTBLE_SELF_TEST=FAIL ' . $error->getMessage());
            return self::FAILURE;
        }
    }
}
