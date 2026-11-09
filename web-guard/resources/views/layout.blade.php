@extends('core/base::layouts.master')
@section('content')
@php
    $wgOnline = $agent && \Carbon\Carbon::parse($agent->last_seen_at)->gt(now()->subSeconds(90));
    $wgLock = \Botble\WebGuard\Services\SettingsService::activeLockdown(is_array($config->desired) ? $config->desired : null);
    $wgNav = ['dashboard' => 'nav_dashboard', 'incidents' => 'nav_incidents', 'bans' => 'nav_bans', 'allowlist' => 'nav_allowlist',
        'paths' => 'nav_paths', 'settings' => 'nav_settings', 'audit' => 'nav_audit', 'setup' => 'nav_setup'];
@endphp
<div class="wg-shell">
    <div class="wg-heading"><div><span class="wg-eyebrow">{{ $t('eyebrow') }}</span><h1>Web Guard</h1><p>{{ $t('subtitle') }}</p></div>
        <div><span class="wg-badge {{ $wgOnline ? 'wg-green' : 'wg-red' }}">{{ $wgOnline ? $t('agent_online') : $t('agent_offline') }}</span>
        <span class="wg-badge">{{ $agent->mode ?? $t('mode_waiting') }}</span></div></div>
    <nav class="wg-tabs" aria-label="Web Guard">
        @foreach($wgNav as $key => $labelKey)
            @if(auth()->user()->hasPermission('web-guard.'.$key))
                <a class="{{ $page === $key ? 'active' : '' }}" href="{{ route('web-guard.'.$key) }}">{{ $t($labelKey) }}</a>
            @endif
        @endforeach
    </nav>
    @if(session('wg_success'))<div class="wg-notice wg-green" role="status">{{ session('wg_success') }}</div>@endif
    @if($errors->any())<div class="wg-notice wg-red" role="alert">@foreach($errors->all() as $error)<div>{{ $error }}</div>@endforeach</div>@endif
    @if($config->revision !== $config->applied_revision)
        <div class="wg-notice wg-amber">{{ $t('notice_revision', ['revision' => $config->revision, 'applied' => $config->applied_revision]) }} {{ $config->last_error ?: $t('notice_pending') }}</div>
    @endif
    @if(!$agent)<div class="wg-notice wg-amber">{{ $t('notice_no_agent') }} @if(auth()->user()->hasPermission('web-guard.setup') && $page !== 'setup')<a href="{{ route('web-guard.setup') }}"><strong>{{ $t('notice_open_setup') }}</strong></a>@endif</div>@endif
    @if($wgLock)<div class="wg-notice wg-red" role="alert"><strong>{{ $t('lockdown_active') }}</strong> {{ $wgLock['level'] === 'full' ? $t('lockdown_full') : $t('lockdown_admin') }} · {{ $t('lockdown_expires', ['time' => \Carbon\Carbon::createFromTimestampUTC($wgLock['until'])->format('Y-m-d H:i')]) }}</div>@endif
    @yield('wg_content')
    <div class="wg-footnote">{{ $t('footnote', ['seen' => $agent->last_seen_at ?? '—', 'version' => $agent->version ?? '1.2.0']) }}</div>
</div>
<script type="application/json" id="wg-i18n">{!! json_encode([
    'copy' => $t('js_copy'), 'copied' => $t('js_copied'), 'online' => $t('js_online'), 'no_confirm' => $t('js_no_confirm'),
    'agent_online' => $t('js_agent_online'), 'agent_stale' => $t('js_agent_stale'), 'refresh_failed' => $t('js_refresh_failed'),
    'chart_note' => $t('js_chart_note'),
], JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_UNESCAPED_UNICODE) !!}</script>
@endsection
