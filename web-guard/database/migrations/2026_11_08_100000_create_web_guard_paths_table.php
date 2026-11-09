<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('wg_paths')) {
            return;
        }
        Schema::create('wg_paths', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->string('jail', 24)->index();
            $table->string('type', 12);
            $table->string('value', 80);
            $table->string('note', 255)->nullable();
            $table->boolean('enabled')->default(true);
            $table->unsignedBigInteger('created_by')->nullable();
            $table->timestamps();
            $table->unique(['type', 'value']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('wg_paths');
    }
};
