<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Support;

use Illuminate\Database\Schema\Blueprint;

/**
 * Adds/drops the four two-factor columns on the host users table. Column names
 * are read from config('two-factor.columns') so hosts with a bespoke schema can
 * remap them. Registered as the `twoFactorColumns()` / `dropTwoFactorColumns()`
 * Blueprint macros by the service provider.
 */
final class TwoFactorColumns
{
    public static function add(Blueprint $table): void
    {
        $columns = self::columns();

        $table->text($columns['secret'])->nullable();
        $table->text($columns['recovery_codes'])->nullable();
        $table->timestamp($columns['confirmed_at'])->nullable();
        $table->unsignedBigInteger($columns['last_used_timestep'])->nullable();
    }

    public static function drop(Blueprint $table): void
    {
        $table->dropColumn(array_values(self::columns()));
    }

    /**
     * @return array{secret: string, recovery_codes: string, confirmed_at: string, last_used_timestep: string}
     */
    private static function columns(): array
    {
        /** @var array{secret: string, recovery_codes: string, confirmed_at: string, last_used_timestep: string} $columns */
        $columns = config('two-factor.columns');

        return $columns;
    }
}
