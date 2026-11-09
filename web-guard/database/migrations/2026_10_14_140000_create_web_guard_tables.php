<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $tables = ['wg_configurations', 'wg_agents', 'wg_events', 'wg_bans', 'wg_allowlist', 'wg_commands', 'wg_audit', 'wg_nonces'];
        $existing = array_filter($tables, fn (string $table): bool => Schema::hasTable($table));
        if (count($existing) === count($tables) && Schema::hasColumn('wg_configurations', 'module_version')
            && DB::table('wg_configurations')->where('id', 1)->value('module_version') === '1.1.0') {
            return;
        }
        if ($existing) {
            throw new \RuntimeException('Tabela wg_* ekzistuese ose të pjesshme. Kërkohet kontroll; nuk mbishkruhen.');
        }
        Schema::create('wg_configurations', function (Blueprint $table): void {
            $table->unsignedTinyInteger('id')->primary();
            $table->string('module_version', 12)->default('1.1.0');
            $table->char('instance_id', 32)->nullable();
            $table->unsignedBigInteger('revision')->default(0);
            $table->json('desired')->nullable();
            $table->unsignedBigInteger('applied_revision')->default(0);
            $table->json('applied')->nullable();
            $table->text('last_error')->nullable();
            $table->unsignedBigInteger('updated_by')->nullable();
            $table->timestamps();
        });
        DB::table('wg_configurations')->insert(['id' => 1, 'created_at' => now(), 'updated_at' => now()]);
        Schema::create('wg_agents', function (Blueprint $table): void {
            $table->char('instance_id', 32)->primary();
            $table->timestamp('last_seen_at')->nullable()->index();
            $table->string('version', 30);
            $table->string('mode', 20);
            $table->json('metrics');
            $table->text('last_error')->nullable();
            $table->timestamps();
        });
        Schema::create('wg_events', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->char('event_id', 32)->unique();
            $table->char('instance_id', 32)->index();
            $table->timestamp('occurred_at')->useCurrent()->index();
            $table->string('event', 40)->index();
            $table->string('ip', 45)->nullable()->index();
            $table->string('rule', 32)->nullable();
            $table->string('method', 12)->nullable();
            $table->string('path', 512)->nullable();
            $table->unsignedSmallInteger('http_status')->nullable();
            $table->json('details')->nullable();
            $table->timestamp('created_at')->useCurrent();
        });
        Schema::create('wg_bans', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->char('instance_id', 32);
            $table->string('ip', 45);
            $table->string('status', 24)->index();
            $table->timestamp('expires_at')->nullable()->index();
            $table->timestamp('edge_checked_at')->nullable();
            $table->json('rules')->nullable();
            $table->timestamps();
            $table->unique(['instance_id', 'ip']);
        });
        Schema::create('wg_allowlist', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->string('cidr', 64)->unique();
            $table->string('label', 255)->nullable();
            $table->unsignedBigInteger('created_by')->nullable();
            $table->timestamps();
        });
        Schema::create('wg_commands', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->string('type', 24);
            $table->json('payload');
            $table->string('status', 20)->default('pending')->index();
            $table->char('lease_token', 32)->nullable();
            $table->timestamp('lease_until')->nullable();
            $table->unsignedInteger('attempts')->default(0);
            $table->json('result')->nullable();
            $table->unsignedBigInteger('requested_by')->nullable();
            $table->timestamps();
        });
        Schema::create('wg_audit', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->unsignedBigInteger('actor_id')->nullable();
            $table->string('action', 40);
            $table->string('target', 80)->nullable();
            $table->json('details')->nullable();
            $table->timestamp('created_at')->useCurrent()->index();
        });
        Schema::create('wg_nonces', function (Blueprint $table): void {
            $table->char('nonce', 32)->primary();
            $table->timestamp('seen_at')->useCurrent()->index();
        });
    }

    public function down(): void
    {
        foreach (['wg_nonces', 'wg_audit', 'wg_commands', 'wg_allowlist', 'wg_bans', 'wg_events', 'wg_agents', 'wg_configurations'] as $name) {
            Schema::dropIfExists($name);
        }
    }
};
