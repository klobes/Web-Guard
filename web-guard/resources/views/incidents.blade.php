@extends('plugins/web-guard::layout')
@section('wg_content')
<section class="wg-card"><div class="wg-card-head"><h2>{{ $t('inc_title') }}</h2><span class="wg-subtle">{{ $t('inc_count', ['count' => $rows->total()]) }}</span></div>
<form method="get" class="wg-filters"><input class="form-control" name="ip" placeholder="{{ $t('inc_filter_ip') }}" value="{{ request('ip') }}"><select class="form-select" name="event"><option value="">{{ $t('inc_all_events') }}</option>@foreach(['SUSPICIOUS_REQUEST','WOULD_BAN','BAN_REQUESTED','BAN_EDGE','UNBAN_REQUESTED','UNBAN_EDGE','ERROR','IGNORED'] as $event)<option value="{{ $event }}" @selected(request('event')===$event)>{{ $event }}</option>@endforeach</select><button class="btn btn-primary">{{ $t('filter') }}</button><a class="btn btn-secondary" href="{{ route('web-guard.incidents') }}">{{ $t('clear') }}</a></form>
<div class="wg-table-wrap"><table class="wg-table"><thead><tr><th>{{ $t('col_time') }}</th><th>IP</th><th>{{ $t('col_event') }}</th><th>{{ $t('inc_col_method_path') }}</th><th>HTTP</th><th>{{ $t('col_details') }}</th></tr></thead><tbody>
@forelse($rows as $row)<tr><td>{{ $row->occurred_at }}</td><td><code>{{ $row->ip ?? '—' }}</code></td><td><span class="wg-badge">{{ $row->event }}</span><small>{{ $row->rule }}</small></td><td class="wg-path">{{ $row->method }} {{ $row->path }}</td><td>{{ $row->http_status ?? '—' }}</td><td class="wg-path">{{ $row->details }}</td></tr>@empty<tr><td colspan="6" class="wg-empty">{{ $t('inc_empty') }}</td></tr>@endforelse
</tbody></table></div>{{ $rows->links() }}
<p class="wg-subtle">{{ $t('inc_note') }}</p></section>
@endsection
