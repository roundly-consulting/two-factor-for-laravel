<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Support;

use Closure;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Adds/drops the four two-factor columns on a host account table. Column names
 * are read from config('two-factor.columns') so hosts with a bespoke schema can
 * remap them. Registered as the `twoFactorColumns()` / `dropTwoFactorColumns()`
 * Blueprint macros by the service provider — call the macro in your own
 * migration for every additional account table (clients, admins, …).
 */
final class TwoFactorColumns
{
    public static function add(Blueprint $table): void
    {
        self::define($table, static fn (string $column): bool => true);
    }

    /**
     * Adds only the columns `$table` does not have yet — the published migration's
     * `up()`. It ships no `down()` (packages migrate forward only), so
     * `migrate:rollback` leaves the columns in place; skipping them here is what lets
     * the next `migrate`, or a `migrate:refresh`, run again instead of failing on a
     * duplicate column. Checked on the default connection, the one a migration's
     * `Schema::table()` builds on.
     */
    public static function addMissing(Blueprint $table): void
    {
        self::define($table, static fn (string $column): bool => ! Schema::hasColumn($table->getTable(), $column));
    }

    /**
     * The table the published migration stub alters: `two-factor.table`, or
     * `users` when unset or blank. Read here rather than in the stub so the
     * config contract (which scans `src/` only) sees the key as used.
     */
    public static function table(): string
    {
        $table = config('two-factor.table');

        return is_string($table) && $table !== '' ? $table : 'users';
    }

    public static function drop(Blueprint $table): void
    {
        $table->dropColumn(array_values(self::columns()));
    }

    /**
     * @param  Closure(string): bool  $wanted  whether to add the column of that name
     */
    private static function define(Blueprint $table, Closure $wanted): void
    {
        $columns = self::columns();

        if ($wanted($columns['secret'])) {
            $table->text($columns['secret'])->nullable();
        }

        if ($wanted($columns['recovery_codes'])) {
            $table->text($columns['recovery_codes'])->nullable();
        }

        if ($wanted($columns['confirmed_at'])) {
            $table->timestamp($columns['confirmed_at'])->nullable();
        }

        if ($wanted($columns['last_used_timestep'])) {
            $table->unsignedBigInteger($columns['last_used_timestep'])->nullable();
        }
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
