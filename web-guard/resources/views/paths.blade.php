@extends('plugins/web-guard::layout')
@section('wg_content')
@php
    $labels = ['rm-web-probes' => $t('rule_probes_short'), 'rm-web-sensitive' => $t('rule_sensitive_short')];
    $types = ['segment' => $t('type_segment'), 'extension' => $t('type_extension')];
    $settings = $config->desired ?? [];
    $ruleLabels = ['rm-web-probes' => $t('rule_probes_long'), 'rm-web-sensitive' => $t('rule_sensitive_long'), 'rm-web-flood' => $t('rule_flood_long')];
@endphp
<form method="post" action="{{ route('web-guard.rules.save') }}">@csrf<input type="hidden" name="revision" value="{{ $config->revision }}">
<fieldset @disabled(!$config->desired || !auth()->user()->hasPermission('web-guard.settings.edit'))>
<section class="wg-card"><div class="wg-card-head"><h2>{{ $t('rules_title') }}</h2><span class="wg-subtle">{{ $t('revision_line', ['revision' => $config->revision, 'applied' => $config->applied_revision]) }}</span></div>
<div class="wg-table-wrap"><table class="wg-table wg-settings-table"><thead><tr><th>{{ $t('rules_col_rule') }}</th><th>{{ $t('rules_col_active') }}</th><th>{{ $t('rules_col_requests') }}</th><th>{{ $t('rules_col_within') }}</th><th>{{ $t('rules_col_ban') }}</th></tr></thead><tbody>
@foreach($ruleLabels as $jail=>$label)
<tr><td><strong>{{ $label }}</strong><small>{{ $jail }}</small></td><td><select class="form-select" name="jails[{{ $jail }}][enabled]"><option value="1" @selected(old('jails.'.$jail.'.enabled',$settings['jails'][$jail]['enabled'] ?? false))>{{ $t('yes') }}</option><option value="0" @selected(!old('jails.'.$jail.'.enabled',$settings['jails'][$jail]['enabled'] ?? false))>{{ $t('no') }}</option></select></td>
@foreach(['maxretry','findtime','bantime'] as $key)<td><input class="form-control" type="number" min="1" max="{{ $key==='maxretry'?10000:($key==='findtime'?86400:604800) }}" name="jails[{{ $jail }}][{{ $key }}]" value="{{ old('jails.'.$jail.'.'.$key,$settings['jails'][$jail][$key] ?? 1) }}"></td>@endforeach</tr>@endforeach
</tbody></table></div><p class="wg-subtle">{{ $t('rules_note') }}</p>
@if(auth()->user()->hasPermission('web-guard.settings.edit'))<button class="btn btn-primary">{{ $t('rules_save') }}</button>@endif</section>
</fieldset></form>
<section class="wg-card"><div class="wg-card-head"><h2>{{ $t('paths_title') }}</h2></div>
<p>{!! $t('paths_intro') !!}</p>
@if(auth()->user()->hasPermission('web-guard.paths.edit'))
<form method="post" action="{{ route('web-guard.paths.add') }}" class="wg-filters">@csrf
    <select class="form-select" name="jail" required>@foreach($labels as $key=>$label)<option value="{{ $key }}" @selected(old('jail')===$key)>{{ $label }}</option>@endforeach</select>
    <select class="form-select" name="type" required>@foreach($types as $key=>$label)<option value="{{ $key }}" @selected(old('type')===$key)>{{ $label }}</option>@endforeach</select>
    <input class="form-control" required name="value" maxlength="80" value="{{ old('value') }}" placeholder="{{ $t('paths_ph_value') }}">
    <input class="form-control" name="note" maxlength="255" value="{{ old('note') }}" placeholder="{{ $t('paths_ph_note') }}">
    <button class="btn btn-primary" @disabled(!$config->desired)>{{ $t('paths_add') }}</button>
</form>
<p class="wg-subtle">{!! $t('paths_help') !!}</p>
@endif
<div class="wg-table-wrap"><table class="wg-table"><thead><tr><th>{{ $t('rules_col_rule') }}</th><th>{{ $t('paths_col_type') }}</th><th>{{ $t('paths_col_value') }}</th><th>{{ $t('paths_col_note') }}</th><th>{{ $t('paths_col_state') }}</th><th>{{ $t('col_action') }}</th></tr></thead><tbody>
@forelse($rows as $row)<tr>
<td>{{ $labels[$row->jail] ?? $row->jail }}</td><td>{{ $types[$row->type] ?? $row->type }}</td><td><code>{{ $row->value }}</code></td><td>{{ $row->note }}</td>
<td><span class="wg-badge {{ $row->enabled ? 'wg-green' : 'wg-amber' }}">{{ $row->enabled ? $t('state_active') : $t('state_inactive') }}</span></td>
<td>@if(auth()->user()->hasPermission('web-guard.paths.edit'))
<form method="post" action="{{ route('web-guard.paths.toggle', $row->id) }}" style="display:inline">@csrf<button class="btn btn-sm btn-outline-primary">{{ $row->enabled ? $t('deactivate') : $t('activate') }}</button></form>
<form method="post" action="{{ route('web-guard.paths.delete', $row->id) }}" style="display:inline" data-wg-confirm="{{ $t('paths_confirm_remove') }}">@csrf @method('DELETE')<button class="btn btn-sm btn-outline-danger">{{ $t('remove') }}</button></form>
@else — @endif</td></tr>
@empty<tr><td colspan="6" class="wg-empty">{{ $t('paths_empty') }}</td></tr>@endforelse
</tbody></table></div>
<p class="wg-subtle">{{ $t('paths_footer') }}</p></section>
@endsection
