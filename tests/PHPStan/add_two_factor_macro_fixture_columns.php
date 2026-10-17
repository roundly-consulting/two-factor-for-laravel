<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Static-analysis fixture (never executed): a host migration calling the schema macros, analysed
 * by `composer analyse` so they stay visible to Larastan without a booted provider.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->twoFactorColumns();
        });

        Schema::table('admins', function (Blueprint $table): void {
            $table->dropTwoFactorColumns();
        });
    }
};
