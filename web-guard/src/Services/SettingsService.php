<?php

namespace Botble\WebGuard\Services;

use Botble\WebGuard\Models\Command;
use Botble\WebGuard\Models\Configuration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Validation\ValidationException;

class SettingsService
{
    public const JAILS = ['rm-web-probes', 'rm-web-sensitive', 'rm-web-flood'];

    // Custom path lists are only allowed for the two path-based jails; the engine enforces the same limits.
    public const PATH_JAILS = ['rm-web-probes', 'rm-web-sensitive'];
    public const PATH_TYPES = ['segment', 'extension'];
    public const PATH_LIMIT = 200;
    public const PROTECTED_SEGMENTS = [
        'admin', 'login', 'logout', 'register', 'api', 'storage', 'assets', 'public', 'css', 'js', 'img', 'images',
        'fonts', 'vendor', 'themes', 'build', 'uploads', 'cdn-cgi', '.well-known', 'favicon.ico', 'robots.txt',
        'sitemap.xml', 'index.php', 'manifest.json', 'sw.js', 'radius-manager', 'products', 'product', 'cart',
        'checkout', 'account', 'customer', 'customers', 'search', 'contact', 'blog', 'news',
    ];
    public const PROTECTED_EXTENSIONS = [
        'php', 'html', 'htm', 'js', 'css', 'json', 'xml', 'txt', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico',
        'woff', 'woff2', 'ttf', 'map', 'pdf', 'mp4', 'webm',
    ];

    /** Translated text of this plugin (admin language: English or Albanian). */
    public static function t(string $key, array $replace = []): string
    {
        return (string) trans('plugins/web-guard::web-guard.' . $key, $replace);
    }

    /** Returns an error message, or null when the entry is safe to send to the engine. */
    public static function pathError(string $type, string $value): ?string
    {
        if ($type === 'extension') {
            if (! preg_match('/^[a-z0-9]{1,10}$/D', $value)) {
                return self::t('err_path_ext_format');
            }
            return in_array($value, self::PROTECTED_EXTENSIONS, true) ? self::t('err_path_ext_reserved') : null;
        }
        if (strlen($value) > 80 || ! preg_match('#^[a-z0-9._~-]{1,64}(?:/[a-z0-9._~-]{1,64}){0,3}$#D', $value)) {
            return self::t('err_path_format');
        }
        $parts = explode('/', $value);
        foreach ($parts as $part) {
            if (! preg_match('/[a-z0-9]/', $part)) {
                return self::t('err_path_part');
            }
        }
        return in_array($parts[0], self::PROTECTED_SEGMENTS, true) ? self::t('err_path_reserved') : null;
    }

    public static function validNetwork(string $value): bool
    {
        $parts = explode('/', $value);
        $packed = @inet_pton($parts[0]);
        if ($packed === false || count($parts) > 2) {
            return false;
        }
        return count($parts) === 1 || (ctype_digit($parts[1]) && (int) $parts[1] <= strlen($packed) * 8);
    }

    public const LOCKDOWN_LEVELS = ['off', 'admin', 'full'];
    public const LOCKDOWN_MINUTES = [5, 15, 30, 60, 180, 360, 720, 1440];

    /** True when the address is inside any of the IPs/CIDRs. */
    public static function ipInList(string $ip, array $networks): bool
    {
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return false;
        }
        foreach ($networks as $network) {
            [$base, $bits] = array_pad(explode('/', (string) $network, 2), 2, null);
            $range = @inet_pton((string) $base);
            if ($range === false || strlen($range) !== strlen($packed)) {
                continue;
            }
            $bits = $bits === null ? strlen($range) * 8 : (int) $bits;
            $full = intdiv($bits, 8);
            if (substr($packed, 0, $full) !== substr($range, 0, $full)) {
                continue;
            }
            if ($bits % 8 === 0) {
                return true;
            }
            $mask = (0xFF << (8 - $bits % 8)) & 0xFF;
            if ((ord($packed[$full]) & $mask) === (ord($range[$full]) & $mask)) {
                return true;
            }
        }
        return false;
    }

    /** Active lockdown (level and deadline) from a settings array, or null when off or expired. */
    public static function activeLockdown(?array $settings): ?array
    {
        $lock = $settings['lockdown'] ?? null;
        if (! is_array($lock) || ($lock['level'] ?? 'off') === 'off' || (int) ($lock['until'] ?? 0) <= time()) {
            return null;
        }
        return ['level' => $lock['level'], 'until' => (int) $lock['until']];
    }

    public function audit(string $action, ?string $target = null, array $details = []): void
    {
        DB::table('wg_audit')->insert(['actor_id' => auth()->id(), 'action' => $action, 'target' => $target,
            'details' => json_encode($details, JSON_THROW_ON_ERROR), 'created_at' => now()]);
    }

    public function queueSettings(array $changes = []): Configuration
    {
        return DB::transaction(function () use ($changes): Configuration {
            $config = Configuration::query()->lockForUpdate()->findOrFail(1);
            if (! $config->desired) {
                throw ValidationException::withMessages(['agent' => self::t('err_agent_first')]);
            }
            $desired = array_replace_recursive($config->desired, $changes);
            $desired['ignoreip'] = DB::table('wg_allowlist')->orderBy('id')->pluck('cidr')->all();
            // A lockdown is always timed: an expired one, or one without an allowlist, is never sent again.
            if (isset($desired['lockdown']) && (! self::activeLockdown($desired) || ! $desired['ignoreip'])) {
                $desired['lockdown'] = ['level' => 'off', 'until' => 0];
            }
            if (Schema::hasTable('wg_paths')) {
                $paths = array_fill_keys(self::PATH_JAILS, []);
                foreach (DB::table('wg_paths')->where('enabled', true)->orderBy('id')->get(['jail', 'type', 'value']) as $row) {
                    if (isset($paths[$row->jail])) {
                        $paths[$row->jail][] = ['type' => $row->type, 'value' => $row->value];
                    }
                }
                $desired['paths'] = $paths;
            }
            $config->desired = $desired;
            $config->revision++;
            $config->updated_by = auth()->id();
            $config->last_error = null;
            $config->save();
            Command::query()->where('type', 'apply_settings')->where('status', 'pending')->update(['status' => 'superseded']);
            Command::query()->create(['type' => 'apply_settings', 'payload' => ['revision' => $config->revision, 'settings' => $desired],
                'requested_by' => auth()->id()]);
            $this->audit('settings.queued', (string) $config->revision, $changes);
            return $config;
        });
    }
}
