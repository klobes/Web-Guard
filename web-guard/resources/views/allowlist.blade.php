@extends('plugins/web-guard::layout')
@section('wg_content')
<section class="wg-card"><div class="wg-card-head"><h2>{{ $t('allow_title') }}</h2></div><p>{{ $t('allow_intro') }}</p>
@if(auth()->user()->hasPermission('web-guard.allowlist.edit'))<form method="post" action="{{ route('web-guard.allowlist.add') }}" class="wg-filters">@csrf<input class="form-control" required name="cidr" placeholder="{{ $t('allow_ph_cidr') }}" maxlength="64"><input class="form-control" name="label" placeholder="{{ $t('allow_ph_label') }}" maxlength="255"><button class="btn btn-primary" @disabled(!$config->desired)>{{ $t('allow_add') }}</button></form>@endif
<div class="wg-table-wrap"><table class="wg-table"><thead><tr><th>IP / CIDR</th><th>{{ $t('allow_col_label') }}</th><th>{{ $t('allow_col_added') }}</th><th>{{ $t('col_action') }}</th></tr></thead><tbody>
@forelse($rows as $row)<tr><td><code>{{ $row->cidr }}</code></td><td>{{ $row->label }}</td><td>{{ $row->created_at }}</td><td>@if(auth()->user()->hasPermission('web-guard.allowlist.edit'))<form method="post" action="{{ route('web-guard.allowlist.delete',$row->id) }}" data-wg-confirm="{{ $t('allow_confirm_remove') }}">@csrf @method('DELETE')<button class="btn btn-sm btn-outline-danger">{{ $t('remove') }}</button></form>@else — @endif</td></tr>@empty<tr><td colspan="4" class="wg-empty">{{ $t('allow_empty') }}</td></tr>@endforelse
</tbody></table></div>{{ $rows->links() }}</section>
@endsection
