@extends('plugins/web-guard::layout')
@section('wg_content')
@php
    $done = collect($steps)->filter()->count();
    $total = count($steps);
    $mark = function ($ok) use ($t) {
        return $ok ? '<span class="wg-badge wg-green">'.e($t('setup_done')).'</span>' : '<span class="wg-badge wg-amber">'.e($t('setup_pending')).'</span>';
    };
    $d = e($domain);
    $pkg = 'RM_WEBGUARD_BOTBLE_1.2.0';
@endphp
<section class="wg-card">
    <div class="wg-card-head"><h2>{{ $t('setup_title') }}</h2><span class="wg-badge {{ $done === $total ? 'wg-green' : 'wg-amber' }}">{{ $t('setup_steps_count', ['done' => $done, 'total' => $total]) }}</span></div>
    <p>{{ $t('setup_intro') }}</p>
    <p class="wg-subtle">{{ $t('setup_token_warning') }}</p>
</section>

<section class="wg-card">
    <div class="wg-card-head"><h2>{{ $t('s1_title') }}</h2>{!! $mark($steps['engine']) !!}</div>
    <p>{!! $t('s1_upload', ['pkg' => $pkg]) !!}</p>
    <pre class="wg-json" data-wg-copy>sudo apt install -y fail2ban
sudo systemctl enable --now fail2ban</pre>
    <p>{!! $t('s1_install') !!}</p>
    <pre class="wg-json" data-wg-copy>tar -xzf /tmp/{{ $pkg }}.tar.gz -C /tmp
sudo bash /tmp/{{ $pkg }}/install.sh /var/www/html/MartFury</pre>
    <p>{!! $t('s1_wait') !!}</p>
    <pre class="wg-json" data-wg-copy>sudo systemctl status rm-webguard-panel.service --no-pager
sudo journalctl -u rm-webguard-panel.service -n 50 --no-pager</pre>
    <p class="wg-subtle">Fail2ban: {!! $mark($steps['fail2ban']) !!}</p>
    <p class="wg-subtle">{!! $t('s1_update') !!}</p>
</section>

<section class="wg-card">
    <div class="wg-card-head"><h2>{{ $t('s2_title') }}</h2>{!! $mark($steps['allowlist']) !!}</div>
    <p>{!! $t('s2_text', ['ip' => e($myIp)]) !!}</p>
    @if(auth()->user()->hasPermission('web-guard.allowlist'))<p><a class="btn btn-sm btn-outline-primary" href="{{ route('web-guard.allowlist') }}">{{ $t('s2_open') }}</a></p>@endif
</section>

<section class="wg-card">
    <div class="wg-card-head"><h2>{{ $t('s3_title') }}</h2><span class="wg-badge">{{ $t('s3_badge') }}</span></div>
    <ol>
        <li>{!! $t('s3_l1') !!}</li>
        <li>{!! $t('s3_l2') !!}</li>
        <li>{!! $t('s3_l3', ['domain' => $d]) !!}</li>
        <li>{!! $t('s3_l4') !!}</li>
    </ol>
</section>

<section class="wg-card">
    <div class="wg-card-head"><h2>{{ $t('s4_title') }}</h2>{!! $mark($steps['token']) !!}</div>
    <p>{!! $t('s4_text') !!}</p>
    <pre class="wg-json" data-wg-copy>sudo rm-webguard token</pre>
    <p>{!! $t('s4_roll') !!}</p>
</section>

<section class="wg-card">
    <div class="wg-card-head"><h2>{{ $t('s5_title') }}</h2>{!! $mark($steps['zone']) !!}</div>
    <p>{!! $t('s5_text', ['domain' => $d]) !!}</p>
    <p>{{ $t('s5_verify') }}</p>
    @if(auth()->user()->hasPermission('web-guard.settings'))<p><a class="btn btn-sm btn-outline-primary" href="{{ route('web-guard.settings') }}">{{ $t('s5_open') }}</a></p>@endif
    <p class="wg-subtle">{{ $t('s5_warn') }}</p>
</section>

<section class="wg-card">
    <div class="wg-card-head"><h2>{{ $t('s6_title') }}</h2>{!! $mark($steps['monitor']) !!}</div>
    <p>{!! $t('s6_text') !!}</p>
    <pre class="wg-json" data-wg-copy>curl -s -o /dev/null -H "Host: {{ $domain }}" http://127.0.0.1:5555/.env
sudo tail -n 3 /var/log/rm-webguard/access.log</pre>
    <p>{!! $t('s6_real', ['domain' => $d]) !!}</p>
    @if(auth()->user()->hasPermission('web-guard.incidents'))<p><a class="btn btn-sm btn-outline-primary" href="{{ route('web-guard.incidents') }}">{{ $t('s6_open') }}</a></p>@endif
</section>

<section class="wg-card">
    <div class="wg-card-head"><h2>{{ $t('s7_title') }}</h2>{!! $mark($steps['enforce']) !!}</div>
    <ol>
        <li>{!! $t('s7_l1') !!}</li>
        <li>{{ $t('s7_l2') }}</li>
        <li>{!! $t('s7_l3') !!}</li>
    </ol>
    <p>{!! $t('s7_test') !!}</p>
    <pre class="wg-json" data-wg-copy>sudo rm-webguard status
sudo rm-webguard unban 203.0.113.10</pre>
    <p class="wg-subtle">{!! $t('s7_warn') !!}</p>
</section>

<section class="wg-card">
    <div class="wg-card-head"><h2>{{ $t('s8_title') }}</h2><span class="wg-badge">{{ $t('s8_badge') }}</span></div>
    <ul>
        <li>{!! $t('s8_rules') !!}
            @if(auth()->user()->hasPermission('web-guard.paths'))<a href="{{ route('web-guard.paths') }}">{{ $t('s8_rules_open') }}</a>@endif</li>
        <li>{!! $t('s8_admin') !!}</li>
        <li>{!! $t('s8_cleanup') !!}</li>
        <li>{!! $t('s8_roles') !!}</li>
        <li>{!! $t('s8_lockdown') !!}</li>
    </ul>
</section>

<section class="wg-card">
    <div class="wg-card-head"><h2>{{ $t('s9_title') }}</h2></div>
    <pre class="wg-json" data-wg-copy>sudo rm-webguard status
sudo systemctl status rm-webguard-panel.service --no-pager
sudo fail2ban-client status
cd {{ $appPath }} &amp;&amp; sudo -u www-data php artisan web-guard:self-test</pre>
    <p class="wg-subtle">{!! $t('s9_stop') !!}</p>
</section>
@endsection
