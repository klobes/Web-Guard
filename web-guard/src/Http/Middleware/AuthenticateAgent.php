<?php

namespace Botble\WebGuard\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class AuthenticateAgent
{
    public function handle(Request $request, Closure $next)
    {
        // Use the server value, never a client-supplied forwarding header.
        abort_unless(in_array($request->server('REMOTE_ADDR'), ['127.0.0.1', '::1'], true), 403);
        $body = $request->getContent();
        abort_if(strlen($body) > 2 * 1024 * 1024, 413);
        $stamp = (string) $request->header('X-WebGuard-Time', '');
        $nonce = (string) $request->header('X-WebGuard-Nonce', '');
        $signature = (string) $request->header('X-WebGuard-Signature', '');
        $path = config('plugins.web-guard.general.bridge_key_file');
        $key = is_string($path) && is_readable($path) ? trim((string) file_get_contents($path)) : '';
        abort_unless(strlen($key) === 64 && ctype_xdigit($key) && ctype_digit($stamp)
            && abs(time() - (int) $stamp) <= 60 && preg_match('/^[a-f0-9]{32}$/D', $nonce)
            && preg_match('/^[a-f0-9]{64}$/D', $signature), 403);
        $expected = hash_hmac('sha256', $stamp . "\n" . $nonce . "\n" . $body, $key);
        abort_unless(hash_equals($expected, $signature), 403);
        DB::table('wg_nonces')->where('seen_at', '<', now()->subMinutes(2))->delete();
        abort_unless(DB::table('wg_nonces')->insertOrIgnore(['nonce' => $nonce, 'seen_at' => now()]) === 1, 409);
        return $next($request);
    }
}
