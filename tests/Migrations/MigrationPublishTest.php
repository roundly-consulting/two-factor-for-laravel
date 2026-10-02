<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
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
it('runs the published migration against the configured account table', function () use ($stub): void {
    // A clean host table the package's columns have NOT already been added to (the suite's
    // own `users` fixture already carries them) — a second account table, the case
    // `two-factor.table` exists for.
    Schema::create('clients', function (Blueprint $table): void {
        $table->id();
        $table->string('email');
    });

    config(['two-factor.table' => 'clients']);

    // Copied byte-for-byte: the config key alone must steer the shipped file, exactly as it
    // does in a host that published it.
    $directory = sys_get_temp_dir().'/two-factor-publish-'.Str::random(8);
    mkdir($directory);
    $file = $directory.'/2026_01_01_000000_add_two_factor_columns_to_users_table.php';
    copy($stub, $file);

    // Applied directly rather than through `artisan migrate`: the migrator wants its own
    // repository table and a batch number, none of which this is testing. What is being
    // tested is that the shipped `up()` runs — on whatever driver the leg configured, so
    // the pgsql leg puts this stub in front of a real engine.
    $migration = require $file;

    expect($migration)->toBeInstanceOf(Migration::class);

    $migration->up();

    expect(Schema::hasColumns('clients', [
        'two_factor_secret',
        'two_factor_recovery_codes',
        'two_factor_confirmed_at',
        'two_factor_last_used_timestep',
    ]))->toBeTrue();

    // The types are the half only a real engine checks: sqlite reports `unsignedBigInteger`
    // and `integer` alike, so a width regression here is invisible until the pgsql leg.
    expect(Schema::getColumnType('clients', 'two_factor_last_used_timestep'))
        ->toBe(DriverMatrix::driver() === 'pgsql' ? 'int8' : 'integer');

    Schema::drop('clients');
    array_map(unlink(...), (array) glob($directory.'/*'));
    rmdir($directory);
});

/**
 * Forward-only, like every roundly migration: the stub ships no `down()`, so
 * `migrate:rollback` drops the migration record and leaves the columns in place. The next
 * `migrate` — and every `migrate:refresh` — then runs `up()` over a table that already has
 * them, which used to fail on a duplicate `two_factor_secret` column. `up()` adds only the
 * columns that are missing, so the real artisan sequence goes through end to end.
 */
it('survives migrate, rollback, migrate and refresh without a down()', function () use ($stub): void {
    Schema::create('clients', function (Blueprint $table): void {
        $table->id();
        $table->string('email');
    });

    config(['two-factor.table' => 'clients']);

    $directory = sys_get_temp_dir().'/two-factor-rerun-'.Str::random(8);
    mkdir($directory);
    copy($stub, $directory.'/2026_01_01_000000_add_two_factor_columns_to_users_table.php');

    $options = ['--path' => $directory, '--realpath' => true, '--force' => true];
    $columns = [
        'two_factor_secret',
        'two_factor_recovery_codes',
        'two_factor_confirmed_at',
        'two_factor_last_used_timestep',
    ];

    expect(Artisan::call('migrate', $options))->toBe(0)
        ->and(Schema::hasColumns('clients', $columns))->toBeTrue();

    // Rollback forgets the migration and leaves the columns — there is nothing to unwind with.
    expect(Artisan::call('migrate:rollback', $options))->toBe(0)
        ->and(Schema::hasColumns('clients', $columns))->toBeTrue();

    expect(Artisan::call('migrate', $options))->toBe(0)
        ->and(Artisan::call('migrate:refresh', $options))->toBe(0)
        ->and(Schema::hasColumns('clients', array_merge(['email'], $columns)))->toBeTrue();

    Schema::drop('clients');
    array_map(unlink(...), (array) glob($directory.'/*'));
    rmdir($directory);
});

/**
 * The partial case: a table that already carries some of the columns (a run a
 * non-transactional engine interrupted half-way, or a hand-added column) gets only the
 * rest, under the names `two-factor.columns` maps them to, and the existing one is left alone.
 */
it('adds only the configured columns the table does not have yet', function () use ($stub): void {
    config([
        'two-factor.table' => 'clients',
        'two-factor.columns' => [
            'secret' => 'mfa_secret',
            'recovery_codes' => 'mfa_recovery_codes',
            'confirmed_at' => 'mfa_confirmed_at',
            'last_used_timestep' => 'mfa_last_used_timestep',
        ],
    ]);

    Schema::create('clients', function (Blueprint $table): void {
        $table->id();
        $table->string('mfa_secret')->default('kept');
    });

    DB::table('clients')->insert(['id' => 1]);

    $migration = require $stub;
    $migration->up();
    $migration->up();

    expect(Schema::hasColumns('clients', [
        'mfa_secret',
        'mfa_recovery_codes',
        'mfa_confirmed_at',
        'mfa_last_used_timestep',
    ]))->toBeTrue()
        ->and(Schema::hasColumn('clients', 'two_factor_secret'))->toBeFalse()
        ->and(DB::table('clients')->value('mfa_secret'))->toBe('kept');

    Schema::drop('clients');
});

it('ships a stub that names its table only through the config-driven helper', function () use ($stub): void {
    $body = (string) file_get_contents($stub);

    // A literal table name here would silently ignore `two-factor.table`. And no `down()`:
    // packages migrate forward only — re-running `up()` is what has to be safe.
    expect(preg_match("/Schema::table\\(\\s*'/", $body))->toBe(0)
        ->and(substr_count($body, 'Schema::table(TwoFactorColumns::table()'))->toBe(1)
        ->and($body)->not->toContain('function down(');
});
