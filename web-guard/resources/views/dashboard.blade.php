@extends('plugins/web-guard::layout')
@section('wg_content')
<div id="wg-dashboard" data-endpoint="{{ route('web-guard.metrics') }}">
    <div class="wg-kpis">
        <div class="wg-card wg-kpi"><span>{{ $t('dash_kpi_scans') }}</span><strong data-wg="suspicious">{{ $summary['suspicious'] }}</strong><small>{{ $t('dash_kpi_scans_note') }}</small></div>
        <div class="wg-card wg-kpi"><span>{{ $t('dash_kpi_blocked') }}</span><strong data-wg="active">{{ $summary['active'] }}</strong><small>{!! $t('dash_kpi_blocked_note', ['count' => '<b data-wg="pending">'.(int) $summary['pending'].'</b>']) !!}</small></div>
        <div class="wg-card wg-kpi"><span>{{ $t('dash_kpi_monitor') }}</span><strong data-wg="monitor_decisions">{{ $summary['monitor_decisions'] }}</strong><small>{{ $t('dash_kpi_monitor_note') }}</small></div>
        <div class="wg-card wg-kpi"><span>{{ $t('dash_kpi_cpu') }}</span><strong><span id="wg-cpu">{{ $summary['metrics']['cpu_percent'] ?? '—' }}</span><em>%</em></strong><small>{!! $t('dash_kpi_cpu_note', ['load' => '<b id="wg-load">'.e($summary['metrics']['load1'] ?? '—').'</b>', 'cpus' => e($summary['metrics']['cpu_count'] ?? '—')]) !!}</small></div>
    </div>
    <div id="wg-live-alert" class="wg-notice {{ $summary['online'] ? 'wg-green' : 'wg-red' }}">{{ $summary['online'] ? $t('dash_live_ok') : $t('dash_live_stale') }}</div>
    <div class="wg-grid-main">
        <section class="wg-card"><div class="wg-card-head"><h2>{{ $t('dash_chart_title') }}</h2><span class="wg-subtle">{{ $t('dash_chart_unit') }}</span></div>
            <div class="wg-legend"><span class="wg-dot blue"></span>{{ $t('dash_legend_attempts') }} <span class="wg-dot green"></span>{{ $t('dash_legend_bans') }} <span class="wg-dot amber"></span>{{ $t('dash_legend_monitor') }}</div>
            <svg id="wg-chart" viewBox="0 0 720 220" role="img" aria-label="{{ $t('dash_chart_aria') }}"></svg>
            <div class="wg-subtle" id="wg-chart-range">{{ $t('dash_chart_source') }}</div>
        </section>
        <section class="wg-card"><div class="wg-card-head"><h2>{{ $t('dash_status_title') }}</h2></div><dl class="wg-status-list">
            <div><dt>{{ $t('dash_status_mode') }}</dt><dd id="wg-mode">{{ $summary['mode'] }}</dd></div>
            <div><dt>Fail2ban</dt><dd id="wg-f2b">{{ ($summary['metrics']['fail2ban_online'] ?? false) ? $t('js_online') : $t('js_no_confirm') }}</dd></div>
            <div><dt>{{ $t('dash_status_token') }}</dt><dd>{{ ($summary['metrics']['token_ready'] ?? false) ? $t('dash_token_stored') : $t('dash_token_missing') }}</dd></div>
            <div><dt>{{ $t('dash_status_api') }}</dt><dd id="wg-api-success">{{ !empty($summary['metrics']['api_last_success']) ? \Carbon\Carbon::createFromTimestampUTC((int)$summary['metrics']['api_last_success'])->toDateTimeString() : $t('js_no_confirm') }}</dd></div>
            <div><dt>{{ $t('dash_status_commands') }}</dt><dd data-wg="commands_pending">{{ $summary['commands_pending'] }}</dd></div>
            <div><dt>{{ $t('dash_status_queue') }}</dt><dd id="wg-queue">{{ $summary['metrics']['queued_events'] ?? '—' }}</dd></div>
            <div><dt>{{ $t('dash_status_dropped') }}</dt><dd id="wg-dropped">{{ $summary['metrics']['dropped_events'] ?? 0 }}</dd></div>
            <div><dt>{{ $t('dash_status_applied') }}</dt><dd><span data-wg="applied_revision">{{ $summary['applied_revision'] }}</span> / <span data-wg="revision">{{ $summary['revision'] }}</span></dd></div>
        </dl><p class="wg-subtle">{{ $t('dash_status_note') }}</p>
        <div id="wg-agent-error" class="wg-error">{{ $summary['last_error'] ?? '' }}</div></section>
    </div>
    <div class="wg-grid-main">
        <section class="wg-card"><div class="wg-card-head"><h2>{{ $t('dash_recent_title') }}</h2>@if(auth()->user()->hasPermission('web-guard.incidents'))<a href="{{ route('web-guard.incidents') }}">{{ $t('dash_recent_all') }}</a>@endif</div>
            <div class="wg-table-wrap"><table class="wg-table"><thead><tr><th>{{ $t('col_time') }}</th><th>IP</th><th>{{ $t('col_event') }}</th><th>{{ $t('dash_col_path_rule') }}</th></tr></thead><tbody>
            @forelse($recent as $row)<tr><td>{{ $row->occurred_at }}</td><td><code>{{ $row->ip ?? '—' }}</code></td><td><span class="wg-badge">{{ $row->event }}</span></td><td class="wg-path">{{ $row->path ?? $row->rule ?? '—' }}</td></tr>
            @empty<tr><td colspan="4" class="wg-empty">{{ $t('dash_recent_empty') }}</td></tr>@endforelse
            </tbody></table></div><p class="wg-subtle">{{ $t('dash_recent_note') }}</p>
        </section>
        <section class="wg-card"><div class="wg-card-head"><h2>{{ $t('dash_top_title') }}</h2><span class="wg-subtle">24h</span></div>
            @forelse($topIps as $row)<div class="wg-top-ip"><code>{{ $row->ip }}</code><strong>{{ $row->total }}</strong></div>@empty<div class="wg-empty">{{ $t('dash_top_empty') }}</div>@endforelse
        </section>
    </div>
</div>
<script type="application/json" id="wg-initial">{!! json_encode($summary, JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT) !!}</script>
@endsection
