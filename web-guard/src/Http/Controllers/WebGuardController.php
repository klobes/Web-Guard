<?php

namespace Botble\WebGuard\Http\Controllers;

use Botble\Base\Facades\Assets;
use Botble\Base\Http\Controllers\BaseController;
use Botble\WebGuard\Models\Command;
use Botble\WebGuard\Models\Configuration;
use Botble\WebGuard\Services\SettingsService;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

class WebGuardController extends BaseController
{
    private function permit(string $flag): void
    {
        abort_unless(auth()->user()?->hasPermission('web-guard.' . $flag), 403);
    }

    private function page(string $page, array $data = [])
    {
        $this->pageTitle('Web Guard');
        Assets::addStylesDirectly('vendor/core/plugins/web-guard/css/webguard.css');
        Assets::addScriptsDirectly('vendor/core/plugins/web-guard/js/webguard.js');
        return view('plugins/web-guard::' . $page, $data + ['page' => $page,
            'config' => Configuration::query()->findOrFail(1), 'agent' => DB::table('wg_agents')->first()]);
    }

    private function desired(): ?array
    {
        $desired = Configuration::query()->find(1)?->desired;
        return is_array($desired) ? $desired : null;
    }

    private function summary(): array
    {
        $agent = DB::table('wg_agents')->first();
        $metrics = $agent ? json_decode($agent->metrics, true) : [];
        $config = Configuration::query()->findOrFail(1);
        $since = now()->subDay();
        $events = DB::table('wg_events')->where('occurred_at', '>=', $since);
        $groups = (clone $events)->selectRaw('event, COUNT(*) AS total')->groupBy('event')->pluck('total', 'event');
        $buckets = (clone $events)->selectRaw("DATE_FORMAT(occurred_at, '%Y-%m-%d %H:00:00') AS hour, event, COUNT(*) AS total")
            ->whereIn('event', ['SUSPICIOUS_REQUEST', 'BAN_EDGE', 'WOULD_BAN'])->groupBy('hour', 'event')->get();
        $chart = [];
        for ($i = 23; $i >= 0; $i--) {
            $hour = now()->subHours($i)->startOfHour();
            $rows = $buckets->where('hour', $hour->format('Y-m-d H:00:00'));
            $chart[] = ['hour' => $hour->format('H:i'), 'requests' => (int) $rows->where('event', 'SUSPICIOUS_REQUEST')->sum('total'),
                'bans' => (int) $rows->where('event', 'BAN_EDGE')->sum('total'), 'monitor' => (int) $rows->where('event', 'WOULD_BAN')->sum('total')];
        }
        return ['mode' => $agent->mode ?? 'DISCONNECTED',
            'online' => $agent && Carbon::parse($agent->last_seen_at)->gt(now()->subSeconds(config('plugins.web-guard.general.stale_after_seconds', 90))),
            'last_seen' => $agent->last_seen_at ?? null, 'metrics' => $metrics,
            'last_error' => $agent->last_error ?? null,
            'suspicious' => (int) ($groups['SUSPICIOUS_REQUEST'] ?? 0), 'blocked_today' => (int) ($groups['BAN_EDGE'] ?? 0),
            'monitor_decisions' => (int) ($groups['WOULD_BAN'] ?? 0),
            'active' => DB::table('wg_bans')->where('status', 'active')->count(),
            'pending' => DB::table('wg_bans')->whereIn('status', ['pending', 'pending_unban'])->count(),
            'commands_pending' => Command::query()->whereIn('status', ['pending', 'processing'])->count(),
            'revision' => $config->revision, 'applied_revision' => $config->applied_revision, 'chart' => $chart];
    }

    public function setup()
    {
        $this->permit('setup');
        $agent = DB::table('wg_agents')->first();
        $metrics = $agent ? (json_decode($agent->metrics, true) ?: []) : [];
        $config = Configuration::query()->findOrFail(1);
        $desired = is_array($config->desired) ? $config->desired : [];
        $zone = (string) ($desired['zone_id'] ?? '');
        $online = $agent && Carbon::parse($agent->last_seen_at)->gt(now()->subSeconds(config('plugins.web-guard.general.stale_after_seconds', 90)));
        $enforcing = $online && ($desired['enabled'] ?? false) && ! ($desired['dry_run'] ?? true) && $config->applied_revision === $config->revision;
        $steps = [
            'engine' => (bool) $online,
            'fail2ban' => (bool) ($metrics['fail2ban_online'] ?? false),
            'allowlist' => DB::table('wg_allowlist')->exists(),
            'token' => (bool) ($metrics['token_ready'] ?? false),
            'zone' => (bool) preg_match('/^[a-f0-9]{32}$/', $zone),
            'monitor' => DB::table('wg_events')->whereIn('event', ['SUSPICIOUS_REQUEST', 'WOULD_BAN', 'BAN_EDGE'])->exists(),
            'enforce' => $enforcing && ! empty($metrics['api_last_success']),
        ];
        return $this->page('setup', ['steps' => $steps, 'myIp' => request()->ip(),
            'domain' => parse_url(config('app.url'), PHP_URL_HOST) ?: 'klobes.al', 'appPath' => base_path()]);
    }

    public function dashboard()
    {
        $this->permit('dashboard');
        if (! DB::table('wg_agents')->exists() && ! session()->has('wg_setup_seen')) {
            session()->put('wg_setup_seen', true);
            if (auth()->user()?->hasPermission('web-guard.setup')) {
                return redirect()->route('web-guard.setup')->with('wg_success', SettingsService::t('ok_setup_redirect'));
            }
        }
        return $this->page('dashboard', ['summary' => $this->summary(),
            'recent' => DB::table('wg_events')->orderByDesc('id')->limit(10)->get(),
            'topIps' => DB::table('wg_events')->where('event', 'SUSPICIOUS_REQUEST')->where('occurred_at', '>=', now()->subDay())
                ->whereNotNull('ip')->selectRaw('ip, COUNT(*) AS total')->groupBy('ip')->orderByDesc('total')->limit(8)->get()]);
    }

    public function metrics()
    {
        $this->permit('dashboard');
        return response()->json($this->summary());
    }

    public function incidents(Request $request)
    {
        $this->permit('incidents');
        $filters = $request->validate(['ip' => 'nullable|ip', 'event' => 'nullable|in:SUSPICIOUS_REQUEST,WOULD_BAN,BAN_REQUESTED,BAN_EDGE,UNBAN_REQUESTED,UNBAN_EDGE,ERROR,IGNORED']);
        $query = DB::table('wg_events')->orderByDesc('id');
        foreach ($filters as $key => $value) {
            if ($value) {
                $query->where($key, $value);
            }
        }
        return $this->page('incidents', ['rows' => $query->paginate(50)->withQueryString()]);
    }

    public function bans(Request $request)
    {
        $this->permit('bans');
        $filter = $request->validate(['status' => 'nullable|in:active,pending,pending_unban,released']);
        $query = DB::table('wg_bans')->orderByDesc('updated_at');
        if ($filter['status'] ?? null) {
            $query->where('status', $filter['status']);
        }
        return $this->page('bans', ['rows' => $query->paginate(50)->withQueryString()]);
    }

    public function settings()
    {
        $this->permit('settings');
        return $this->page('settings', ['myIp' => request()->ip(),
            'lockdown' => SettingsService::activeLockdown($this->desired())]);
    }

    public function saveSettings(Request $request, SettingsService $service)
    {
        $this->permit('settings.edit');
        $rules = ['revision' => 'required|integer|min:0', 'enabled' => 'required|boolean', 'dry_run' => 'required|boolean',
            'local_firewall' => 'required|boolean', 'increment_bantime' => 'required|boolean',
            'zone_id' => ['nullable', 'regex:/^[a-fA-F0-9]{32}$/D'], 'maximum_bantime_seconds' => 'required|integer|between:1,604800'];
        $data = $request->validate($rules);
        DB::transaction(function () use ($data, $request, $service): void {
            $config = Configuration::query()->lockForUpdate()->findOrFail(1);
            if ((int) $data['revision'] !== $config->revision) {
                throw ValidationException::withMessages(['revision' => SettingsService::t('err_settings_changed')]);
            }
            unset($data['revision']);
            foreach (['enabled', 'dry_run', 'local_firewall', 'increment_bantime'] as $key) {
                $data[$key] = $request->boolean($key);
            }
            $data['zone_id'] = strtolower($data['zone_id'] ?? '');
            $data['maximum_bantime_seconds'] = (int) $data['maximum_bantime_seconds'];
            if ($data['enabled'] && ! $data['dry_run'] && ! $data['zone_id']) {
                throw ValidationException::withMessages(['zone_id' => SettingsService::t('err_zone_required')]);
            }
            foreach (($config->desired['jails'] ?? []) as $jail => $values) {
                if ((int) ($values['bantime'] ?? 0) > $data['maximum_bantime_seconds']) {
                    throw ValidationException::withMessages(['maximum_bantime_seconds' => SettingsService::t('err_max_ban_jail', ['jail' => $jail])]);
                }
            }
            $service->queueSettings($data);
        });
        return back()->with('wg_success', SettingsService::t('ok_settings'));
    }

    public function saveRules(Request $request, SettingsService $service)
    {
        $this->permit('settings.edit');
        $rules = ['revision' => 'required|integer|min:0'];
        foreach (SettingsService::JAILS as $jail) {
            foreach (['enabled' => 'boolean', 'maxretry' => 'integer|between:1,10000', 'findtime' => 'integer|between:1,86400', 'bantime' => 'integer|between:1,604800'] as $key => $validation) {
                $rules['jails.' . $jail . '.' . $key] = 'required|' . $validation;
            }
        }
        $data = $request->validate($rules);
        DB::transaction(function () use ($data, $request, $service): void {
            $config = Configuration::query()->lockForUpdate()->findOrFail(1);
            if ((int) $data['revision'] !== $config->revision) {
                throw ValidationException::withMessages(['revision' => SettingsService::t('err_rules_changed')]);
            }
            $maximum = (int) ($config->desired['maximum_bantime_seconds'] ?? 86400);
            $jails = [];
            foreach (SettingsService::JAILS as $jail) {
                $jails[$jail] = ['enabled' => $request->boolean('jails.' . $jail . '.enabled')];
                foreach (['maxretry', 'findtime', 'bantime'] as $key) {
                    $jails[$jail][$key] = (int) $data['jails'][$jail][$key];
                }
                if ($jails[$jail]['bantime'] > $maximum) {
                    throw ValidationException::withMessages(['jails.' . $jail . '.bantime' => SettingsService::t('err_rules_max', ['max' => $maximum])]);
                }
            }
            $service->queueSettings(['jails' => $jails]);
        });
        return back()->with('wg_success', SettingsService::t('ok_rules'));
    }

    public function saveLockdown(Request $request, SettingsService $service)
    {
        $this->permit('settings.edit');
        $data = $request->validate([
            'level' => 'required|in:' . implode(',', SettingsService::LOCKDOWN_LEVELS),
            'minutes' => 'required_unless:level,off|nullable|integer|in:' . implode(',', SettingsService::LOCKDOWN_MINUTES),
        ]);
        $lock = ['level' => 'off', 'until' => 0];
        if ($data['level'] !== 'off') {
            $allowlist = DB::table('wg_allowlist')->pluck('cidr')->all();
            if (! $allowlist) {
                throw ValidationException::withMessages(['level' => SettingsService::t('err_lock_no_allowlist')]);
            }
            if (! SettingsService::ipInList((string) $request->ip(), $allowlist) && ! $request->boolean('confirm_self')) {
                throw ValidationException::withMessages(['level' => SettingsService::t('err_lock_self', ['ip' => $request->ip()])]);
            }
            $lock = ['level' => $data['level'], 'until' => now()->addMinutes((int) $data['minutes'])->timestamp];
        }
        DB::transaction(function () use ($lock, $service): void {
            Configuration::query()->lockForUpdate()->findOrFail(1);
            $service->audit('lockdown.' . $lock['level'], null, $lock);
            $service->queueSettings(['lockdown' => $lock]);
        });
        return back()->with('wg_success', $lock['level'] === 'off'
            ? SettingsService::t('ok_lock_off')
            : SettingsService::t('ok_lock_on'));
    }

    public function allowlist()
    {
        $this->permit('allowlist');
        return $this->page('allowlist', ['rows' => DB::table('wg_allowlist')->orderBy('id')->paginate(50)]);
    }

    public function addAllowlist(Request $request, SettingsService $service)
    {
        $this->permit('allowlist.edit');
        $request->merge(['cidr' => trim((string) $request->input('cidr', ''))]);
        $data = $request->validate(['cidr' => 'required|string|max:64|unique:wg_allowlist,cidr', 'label' => 'nullable|string|max:255']);
        $data['cidr'] = trim($data['cidr']);
        if (! SettingsService::validNetwork($data['cidr'])) {
            throw ValidationException::withMessages(['cidr' => SettingsService::t('err_cidr')]);
        }
        DB::transaction(function () use ($data, $service): void {
            Configuration::query()->lockForUpdate()->findOrFail(1);
            if (DB::table('wg_allowlist')->count() >= 500) {
                throw ValidationException::withMessages(['cidr' => SettingsService::t('err_allow_limit')]);
            }
            DB::table('wg_allowlist')->insert($data + ['created_by' => auth()->id(), 'created_at' => now(), 'updated_at' => now()]);
            $service->audit('allowlist.add', $data['cidr']);
            $service->queueSettings();
        });
        return back()->with('wg_success', SettingsService::t('ok_allow_added'));
    }

    public function deleteAllowlist(int $id, SettingsService $service)
    {
        $this->permit('allowlist.edit');
        DB::transaction(function () use ($id, $service): void {
            Configuration::query()->lockForUpdate()->findOrFail(1);
            $row = DB::table('wg_allowlist')->find($id);
            abort_unless($row, 404);
            DB::table('wg_allowlist')->where('id', $id)->delete();
            $service->audit('allowlist.remove', $row->cidr);
            $service->queueSettings();
        });
        return back()->with('wg_success', SettingsService::t('ok_allow_removed'));
    }

    public function unban(int $id, SettingsService $service)
    {
        $this->permit('unban');
        $ban = DB::table('wg_bans')->find($id);
        abort_unless($ban, 404);
        DB::transaction(function () use ($ban, $service): void {
            Command::query()->create(['type' => 'unban', 'payload' => ['ip' => $ban->ip], 'requested_by' => auth()->id()]);
            $service->audit('unban.queued', $ban->ip);
        });
        return back()->with('wg_success', SettingsService::t('ok_unban'));
    }

    public function paths()
    {
        $this->permit('paths');
        return $this->page('paths', ['rows' => DB::table('wg_paths')->orderBy('jail')->orderBy('type')->orderBy('value')->get()]);
    }

    public function addPath(Request $request, SettingsService $service)
    {
        $this->permit('paths.edit');
        $request->merge(['value' => strtolower(trim((string) $request->input('value', '')))]);
        $data = $request->validate([
            'jail' => 'required|in:' . implode(',', SettingsService::PATH_JAILS),
            'type' => 'required|in:' . implode(',', SettingsService::PATH_TYPES),
            'value' => 'required|string|max:80',
            'note' => 'nullable|string|max:255',
        ]);
        if ($message = SettingsService::pathError($data['type'], $data['value'])) {
            throw ValidationException::withMessages(['value' => $message]);
        }
        DB::transaction(function () use ($data, $service): void {
            Configuration::query()->lockForUpdate()->findOrFail(1);
            if (DB::table('wg_paths')->where('type', $data['type'])->where('value', $data['value'])->exists()) {
                throw ValidationException::withMessages(['value' => SettingsService::t('err_path_exists')]);
            }
            if (DB::table('wg_paths')->where('jail', $data['jail'])->count() >= SettingsService::PATH_LIMIT) {
                throw ValidationException::withMessages(['value' => SettingsService::t('err_path_limit', ['limit' => SettingsService::PATH_LIMIT])]);
            }
            DB::table('wg_paths')->insert($data + ['enabled' => true, 'created_by' => auth()->id(),
                'created_at' => now(), 'updated_at' => now()]);
            $service->audit('paths.add', $data['value'], ['jail' => $data['jail'], 'type' => $data['type']]);
            $service->queueSettings();
        });
        return back()->with('wg_success', SettingsService::t('ok_path_added'));
    }

    public function togglePath(int $id, SettingsService $service)
    {
        $this->permit('paths.edit');
        DB::transaction(function () use ($id, $service): void {
            Configuration::query()->lockForUpdate()->findOrFail(1);
            $row = DB::table('wg_paths')->find($id);
            abort_unless($row, 404);
            DB::table('wg_paths')->where('id', $id)->update(['enabled' => ! $row->enabled, 'updated_at' => now()]);
            $service->audit($row->enabled ? 'paths.disable' : 'paths.enable', $row->value);
            $service->queueSettings();
        });
        return back()->with('wg_success', SettingsService::t('ok_path_toggled'));
    }

    public function deletePath(int $id, SettingsService $service)
    {
        $this->permit('paths.edit');
        DB::transaction(function () use ($id, $service): void {
            Configuration::query()->lockForUpdate()->findOrFail(1);
            $row = DB::table('wg_paths')->find($id);
            abort_unless($row, 404);
            DB::table('wg_paths')->where('id', $id)->delete();
            $service->audit('paths.remove', $row->value);
            $service->queueSettings();
        });
        return back()->with('wg_success', SettingsService::t('ok_path_removed'));
    }

    public function audit()
    {
        $this->permit('audit');
        return $this->page('audit', ['commands' => Command::query()->orderByDesc('id')->paginate(25, ['*'], 'commands_page'),
            'rows' => DB::table('wg_audit')->orderByDesc('id')->paginate(25, ['*'], 'audit_page')]);
    }
}
