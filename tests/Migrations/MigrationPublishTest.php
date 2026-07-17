<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use RoundlyConsulting\Testing\Database\DriverMatrix;
use RoundlyConsulting\TwoFactor\TwoFactorServiceProvider;

/**
 * P — the publish-only guards. Migrations are publish-only (fleet policy, 2026-07-14):
 * the package loads nothing, the host publishes the migration and runs it. Auto-loading
 * *and* publishing means the host runs both copies — a duplicate-table failure that hit
 * three packages (bug #5).
 *
 * `count: 1` pins the source count so neither check can pass over an empty or relocated
 * directory. That pin is worth more here than in most rows: this package's migration is a
 * `.php.stub`, and the shared file-globbing assertions only match `*.php` — so an empty
 * parse is the realistic failure mode rather than a hypothetical one.
 */
$stub = realpath(__DIR__.'/../../database/migrations').'/add_two_factor_columns_to_users_table.php.stub';

it('never auto-loads its migrations — the host publishes them', function (): void {
    expect(TwoFactorServiceProvider::class)->toNotAutoLoadMigrations();
});

it('publishes its migration timestamp-injected into the host', function (): void {
    expect(TwoFactorServiceProvider::class)->toPublishMigrationsTimestamped('two-factor-migrations', 1);
});

/**
 * Bespoke, kept — no preset equivalent, and it is this package's real `R`.
 *
 * The shared real-engine runner (`toApplyOnConnection`) cannot be adopted here: it globs
 * `*.php` out of a migrations directory, and this package's only migration is a
 * `.php.stub` that ALTERs a table the package does not own. So the proof that the shipped
 * DDL actually runs has to build the host's side itself, which is what this does — and it
 * runs on whatever driver the leg configured, so the pgsql leg puts this stub in front of
 * a real engine for the first time.
 */
it('runs the published migration against a clean host users table', function () use ($stub): void {
    // A clean host table the package's columns have NOT already been added to (the suite's
    // own `users` fixture already carries them).
    Schema::create('publish_probe_users', function (Blueprint $table): void {
        $table->id();
        $table->string('email');
    });

    // The stub names `users`; point it at the probe table, which keeps the shipped file
    // byte-identical to what a host receives while letting it run beside the fixture.
    $directory = sys_get_temp_dir().'/two-factor-publish-'.Str::random(8);
    mkdir($directory);
    $file = $directory.'/2026_01_01_000000_add_two_factor_columns_to_users_table.php';
    file_put_contents($file, str_replace("'users'", "'publish_probe_users'", (string) file_get_contents($stub)));

    // Applied directly rather than through `artisan migrate`: the migrator wants its own
    // repository table and a batch number, none of which this is testing. What is being
    // tested is that the shipped `up()` runs — on whatever driver the leg configured, so
    // the pgsql leg puts this stub in front of a real engine for the first time.
    $migration = require $file;

    expect($migration)->toBeInstanceOf(Migration::class);

    $migration->up();

    expect(Schema::hasColumns('publish_probe_users', [
        'two_factor_secret',
        'two_factor_recovery_codes',
        'two_factor_confirmed_at',
        'two_factor_last_used_timestep',
    ]))->toBeTrue();

    // The types are the half only a real engine checks: sqlite reports `unsignedBigInteger`
    // and `integer` alike, so a width regression here is invisible until the pgsql leg.
    expect(Schema::getColumnType('publish_probe_users', 'two_factor_last_used_timestep'))
        ->toBe(DriverMatrix::driver() === 'pgsql' ? 'int8' : 'integer');

    Schema::drop('publish_probe_users');
    array_map(unlink(...), (array) glob($directory.'/*'));
    rmdir($directory);
});
