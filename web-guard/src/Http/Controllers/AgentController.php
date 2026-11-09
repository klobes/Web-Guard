<?php

namespace Botble\WebGuard\Http\Controllers;

use Botble\WebGuard\Models\Command;
use Botble\WebGuard\Models\Configuration;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;

class AgentController
{
    public function sync(Request $request)
    {
        $data = Validator::make($request->json()->all(), [
            'instance_id' => ['required', 'regex:/^[a-f0-9]{32}$/D'],
            'version' => 'required|string|max:30', 'mode' => 'required|in:MONITOR,ENFORCE,DISABLED',
            'metrics' => 'required|array|max:40', 'last_error' => 'nullable|string|max:1000',
            'active_settings' => 'required|array', 'applied_revision' => 'required|integer|min:0', 'check_only' => 'required|boolean',
            'events' => 'present|array|max:200', 'events.*.id' => ['required', 'regex:/^[a-f0-9]{32}$/D'],
            'events.*.at' => 'required|integer|min:0', 'events.*.event' => 'required|string|max:40',
            'events.*.ip' => 'nullable|ip', 'events.*.rule' => 'nullable|string|max:32',
            'events.*.method' => 'nullable|string|max:12', 'events.*.path' => 'nullable|string|max:512',
            'events.*.http_status' => 'nullable|integer|between:100,599', 'events.*.details' => 'nullable|array|max:12',
            'bans' => 'present|array|max:2000', 'bans_complete' => 'required|boolean',
            'bans.*.ip' => 'required|ip', 'bans.*.status' => 'required|in:active,pending,pending_unban',
            'bans.*.expires_at' => 'nullable|integer|min:0', 'bans.*.edge_checked_at' => 'nullable|integer|min:0',
            'bans.*.rules' => 'present|array|max:3',
            'acks' => 'present|array|max:10', 'acks.*.id' => 'required|integer|min:1',
            'acks.*.lease_token' => ['required', 'regex:/^[a-f0-9]{32}$/D'],
            'acks.*.ok' => 'required|boolean', 'acks.*.message' => 'required|string|max:1000',
        ])->validate();
        // No credentials are accepted or stored through this endpoint.
        $active = $data['active_settings'];
        abort_unless(($active['instance_id'] ?? null) === $data['instance_id']
            && ($active['version'] ?? null) === 1 && is_array($active['ignoreip'] ?? null)
            && count($active['ignoreip']) <= 500 && ! isset($active['token']), 422);

        $answer = DB::transaction(function () use ($data, $active): array {
            $config = Configuration::query()->lockForUpdate()->findOrFail(1);
            abort_if($config->instance_id && $config->instance_id !== $data['instance_id'], 409);
            $initial = null;
            if (! $config->desired) {
                $config->fill(['instance_id' => $data['instance_id'], 'desired' => $active, 'applied' => $active,
                    'revision' => 1, 'applied_revision' => 1])->save();
                foreach ($active['ignoreip'] as $network) {
                    abort_unless(is_string($network) && \Botble\WebGuard\Services\SettingsService::validNetwork($network), 422);
                    DB::table('wg_allowlist')->insertOrIgnore(['cidr' => $network, 'label' => 'Importuar nga motori',
                        'created_at' => now(), 'updated_at' => now()]);
                }
                $initial = 1;
            }
            DB::table('wg_agents')->updateOrInsert(['instance_id' => $data['instance_id']], [
                'last_seen_at' => now(), 'version' => $data['version'], 'mode' => $data['mode'],
                'metrics' => json_encode($data['metrics'], JSON_THROW_ON_ERROR), 'last_error' => $data['last_error'] ?? null,
                'created_at' => now(), 'updated_at' => now(),
            ]);
            foreach ($data['events'] as $event) {
                DB::table('wg_events')->insertOrIgnore([
                    'event_id' => $event['id'], 'instance_id' => $data['instance_id'],
                    'occurred_at' => Carbon::createFromTimestampUTC(min($event['at'], time() + 60)),
                    'event' => $event['event'], 'ip' => $event['ip'] ?? null, 'rule' => $event['rule'] ?? null,
                    'method' => $event['method'] ?? null, 'path' => $event['path'] ?? null,
                    'http_status' => $event['http_status'] ?? null,
                    'details' => json_encode($event['details'] ?? [], JSON_THROW_ON_ERROR), 'created_at' => now(),
                ]);
            }
            $ips = [];
            foreach ($data['bans'] as $ban) {
                $ips[] = $ban['ip'];
                DB::table('wg_bans')->upsert([['instance_id' => $data['instance_id'], 'ip' => $ban['ip'],
                    'status' => $ban['status'],
                    'expires_at' => empty($ban['expires_at']) ? null : Carbon::createFromTimestampUTC($ban['expires_at']),
                    'edge_checked_at' => empty($ban['edge_checked_at']) ? null : Carbon::createFromTimestampUTC($ban['edge_checked_at']),
                    'rules' => json_encode($ban['rules'], JSON_THROW_ON_ERROR), 'created_at' => now(), 'updated_at' => now(),
                ]], ['instance_id', 'ip'], ['status', 'expires_at', 'edge_checked_at', 'rules', 'updated_at']);
            }
            if ($data['bans_complete']) {
                DB::table('wg_bans')->where('instance_id', $data['instance_id'])->whereNotIn('ip', $ips)
                    ->where('status', '!=', 'released')->update(['status' => 'released', 'updated_at' => now()]);
            }
            foreach ($data['acks'] as $ack) {
                $command = Command::query()->lockForUpdate()->find($ack['id']);
                if (! $command || $command->lease_token !== $ack['lease_token'] || $command->status !== 'processing') {
                    continue;
                }
                $command->fill(['status' => $ack['ok'] ? 'done' : 'failed', 'result' => ['message' => $ack['message']],
                    'lease_until' => null])->save();
                DB::table('wg_audit')->insert(['actor_id' => null, 'action' => 'command.' . $command->status,
                    'target' => (string) $command->id, 'details' => json_encode(['message' => $ack['message']], JSON_THROW_ON_ERROR), 'created_at' => now()]);
                if ($command->type === 'apply_settings') {
                    if ($ack['ok'] && ($command->payload['revision'] ?? 0) >= $config->applied_revision) {
                        $config->applied = $active;
                        $config->applied_revision = $command->payload['revision'];
                    }
                    if (($command->payload['revision'] ?? 0) === $config->revision) {
                        $config->last_error = $ack['ok'] ? null : $ack['message'];
                    }
                    $config->save();
                }
            }
            if ($data['applied_revision'] === $config->applied_revision && $config->applied !== $active) {
                $config->applied = $active;
                $config->save();
            }
            // Serial execution: no second command while an earlier lease is alive.
            $expired = Command::query()->where('status', 'processing')->where('lease_until', '<', now());
            (clone $expired)->where('attempts', '>=', 3)->update(['status' => 'failed', 'result' => json_encode(['message' => 'Agent lease expired after 3 attempts.'])]);
            (clone $expired)->where('attempts', '<', 3)->update(['status' => 'pending']);
            $commands = [];
            if (! $data['check_only'] && ! Command::query()->where('status', 'processing')->exists()) {
                $next = Command::query()->where('status', 'pending')->orderBy('id')->lockForUpdate()->first();
                if ($next) {
                    $next->fill(['status' => 'processing', 'lease_token' => bin2hex(random_bytes(16)),
                        'lease_until' => now()->addMinutes(10), 'attempts' => $next->attempts + 1])->save();
                    $commands[] = $next->only(['id', 'type', 'payload', 'lease_token']);
                }
            }
            return ['ok' => true, 'accepted_events' => array_column($data['events'], 'id'),
                'accepted_acks' => array_map(fn (array $ack): string => $ack['id'] . ':' . $ack['lease_token'], $data['acks']),
                'commands' => $commands, 'initial_revision' => $initial];
        });
        return response()->json($answer);
    }
}
