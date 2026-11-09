@extends('plugins/web-guard::layout')
@section('wg_content')
@php
    $settings = $config->desired ?? [];
    $toggles = ['enabled' => $t('set_enabled'), 'dry_run' => $t('set_dry_run'), 'local_firewall' => $t('set_local_firewall'), 'increment_bantime' => $t('set_increment')];
@endphp
<form method="post" action="{{ route('web-guard.settings.save') }}">@csrf<input type="hidden" name="revision" value="{{ $config->revision }}">
<fieldset @disabled(!$config->desired || !auth()->user()->hasPermission('web-guard.settings.edit'))>
<section class="wg-card"><div class="wg-card-head"><h2>{{ $t('set_title') }}</h2><span class="wg-subtle">{{ $t('revision_line', ['revision' => $config->revision, 'applied' => $config->applied_revision]) }}</span></div>
<div class="wg-form-grid">
@foreach($toggles as $key=>$label)
<label><span>{{ $label }}</span><select name="{{ $key }}" class="form-select"><option value="1" @selected(old($key,$settings[$key] ?? true))>{{ $t('state_on') }}</option><option value="0" @selected(!old($key,$settings[$key] ?? true))>{{ $t('state_off') }}</option></select></label>@endforeach
<label><span>Cloudflare Zone ID</span><input class="form-control" name="zone_id" maxlength="32" value="{{ old('zone_id',$settings['zone_id'] ?? '') }}" placeholder="{{ $t('set_zone_ph') }}"></label>
<label><span>{{ $t('set_max_ban') }}</span><input class="form-control" type="number" name="maximum_bantime_seconds" min="1" max="604800" value="{{ old('maximum_bantime_seconds',$settings['maximum_bantime_seconds'] ?? 86400) }}"></label>
</div><p class="wg-subtle">{!! $t('set_help', ['rules' => '<a href="'.e(route('web-guard.paths')).'">'.e($t('nav_paths')).'</a>']) !!}</p>
@if(auth()->user()->hasPermission('web-guard.settings.edit'))<button class="btn btn-primary">{{ $t('set_save') }}</button>@endif</section>
</fieldset></form>
@if(auth()->user()->hasPermission('web-guard.settings.edit'))
<section class="wg-card"><div class="wg-card-head"><h2>{{ $t('lock_title') }}</h2>
<span class="wg-badge {{ $lockdown ? 'wg-red' : 'wg-green' }}">{{ $lockdown ? $t('lock_badge_on', ['time' => \Carbon\Carbon::createFromTimestampUTC($lockdown['until'])->format('H:i')]) : $t('state_inactive') }}</span></div>
<p>{!! $t('lock_intro', ['allowlist' => '<a href="'.e(route('web-guard.allowlist')).'">'.e($t('nav_allowlist')).'</a>']) !!}</p>
<form method="post" action="{{ route('web-guard.lockdown.save') }}" class="wg-filters" data-wg-confirm="{{ $t('lock_confirm') }}">@csrf
    <select class="form-select" name="level" required>
        <option value="admin">{{ $t('lock_level_admin') }}</option>
        <option value="full">{{ $t('lock_level_full') }}</option>
        <option value="off">{{ $t('lock_level_off') }}</option>
    </select>
    <select class="form-select" name="minutes">@foreach(\Botble\WebGuard\Services\SettingsService::LOCKDOWN_MINUTES as $m)<option value="{{ $m }}" @selected($m === 60)>{{ $m >= 60 ? $t('lock_hours', ['n' => $m / 60]) : $t('lock_minutes', ['n' => $m]) }}</option>@endforeach</select>
    <label style="display:flex;align-items:center;gap:6px"><input type="checkbox" name="confirm_self" value="1"> {{ $t('lock_confirm_self', ['ip' => $myIp]) }}</label>
    <button class="btn btn-danger">{{ $t('apply') }}</button>
</form>
<p class="wg-subtle">{!! $t('lock_footer') !!}</p></section>
@endif
@if($config->applied)<details class="wg-card"><summary>{{ $t('set_applied_params') }}</summary><pre class="wg-json">{{ json_encode($config->applied,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES) }}</pre></details>@endif
@endsection
