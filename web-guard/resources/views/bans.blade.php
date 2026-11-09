@extends('plugins/web-guard::layout')
@section('wg_content')
@php
    $banLabels = ['active' => $t('ban_status_active'), 'pending' => $t('ban_status_pending'),
        'pending_unban' => $t('ban_status_pending_unban'), 'released' => $t('ban_status_released')];
@endphp
<section class="wg-card"><div class="wg-card-head"><h2>{{ $t('ban_title') }}</h2></div>
<form method="get" class="wg-filters"><select class="form-select" name="status"><option value="">{{ $t('ban_all_states') }}</option>@foreach(['active' => $t('ban_filter_active'), 'pending' => $t('ban_filter_pending'), 'pending_unban' => $t('ban_filter_pending_unban'), 'released' => $t('ban_filter_released')] as $key=>$label)<option value="{{ $key }}" @selected(request('status')===$key)>{{ $label }}</option>@endforeach</select><button class="btn btn-primary">{{ $t('filter') }}</button></form>
<div class="wg-table-wrap"><table class="wg-table"><thead><tr><th>IP</th><th>{{ $t('ban_col_status') }}</th><th>{{ $t('ban_col_expires') }}</th><th>{{ $t('ban_col_rules') }}</th><th>{{ $t('ban_col_confirmed') }}</th><th>{{ $t('col_action') }}</th></tr></thead><tbody>
@forelse($rows as $row)<tr><td><code>{{ $row->ip }}</code></td><td><span class="wg-badge {{ $row->status==='active'?'wg-red':($row->status==='released'?'wg-green':'wg-amber') }}">{{ $banLabels[$row->status] ?? $row->status }}</span></td><td>{{ $row->expires_at ?? '—' }}</td><td>{{ implode(', ',json_decode($row->rules ?: '[]',true)) }}</td><td>{{ $row->edge_checked_at ?? '—' }}</td><td>
@if($row->status!=='released' && auth()->user()->hasPermission('web-guard.unban'))<form method="post" action="{{ route('web-guard.bans.unban',$row->id) }}">@csrf<button class="btn btn-sm btn-outline-primary">{{ $t('ban_unban') }}</button></form>@else — @endif</td></tr>
@empty<tr><td colspan="6" class="wg-empty">{{ $t('ban_empty') }}</td></tr>@endforelse
</tbody></table></div>{{ $rows->links() }}<p class="wg-subtle">{{ $t('ban_note') }}</p></section>
@endsection
