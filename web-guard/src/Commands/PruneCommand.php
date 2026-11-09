<?php

namespace Botble\WebGuard\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

class PruneCommand extends Command
{
    protected $signature = 'web-guard:prune {--days= : Ditët e historikut}';
    protected $description = 'Pastron historikun e vjetër Web Guard; ruan bllokimet dhe komandat në pritje.';

    public function handle(): int
    {
        $days = $this->option('days') ?? config('plugins.web-guard.general.retention_days', 30);
        if (! ctype_digit((string) $days) || (int) $days < 1 || (int) $days > 3650) {
            $this->error('days duhet 1–3650.');
            return self::FAILURE;
        }
        $cutoff = now()->subDays((int) $days);
        foreach (['wg_events' => 'occurred_at', 'wg_audit' => 'created_at'] as $table => $column) {
            DB::table($table)->where($column, '<', $cutoff)->delete();
        }
        DB::table('wg_bans')->where('status', 'released')->where('updated_at', '<', $cutoff)->delete();
        DB::table('wg_commands')->whereIn('status', ['done', 'failed', 'superseded'])->where('updated_at', '<', $cutoff)->delete();
        DB::table('wg_nonces')->where('seen_at', '<', now()->subMinutes(2))->delete();
        $this->info('WEB_GUARD_PRUNE=PASS');
        return self::SUCCESS;
    }
}
