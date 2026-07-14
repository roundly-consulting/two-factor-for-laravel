<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;
use RoundlyConsulting\TwoFactor\TwoFactorServiceProvider;

/**
 * Migrations are publish-only (fleet policy, 2026-07-14): the package loads
 * nothing, the host publishes the migration and runs it. These pins hold that
 * policy in place and prove the published file actually runs from a clean
 * database.
 */
$migrationsPath = realpath(__DIR__.'/../../database/migrations');
$stub = $migrationsPath.'/add_two_factor_columns_to_users_table.php.stub';

it('never auto-loads its migrations', function () use ($migrationsPath): void {
    $paths = array_map(
        static fn (string $path): string => (string) realpath($path),
        app('migrator')->paths(),
    );

    expect($paths)->not->toContain($migrationsPath);
});

it('publishes the migration under a timestamped host filename', function () use ($stub): void {
    $paths = ServiceProvider::pathsToPublish(
        TwoFactorServiceProvider::class,
        'two-factor-migrations',
    );

    expect($paths)->toHaveCount(1)
        ->and(array_keys($paths)[0])->toBe($stub);

    $destination = array_values($paths)[0];

    expect($destination)->toMatch(
        '#^'.preg_quote(database_path('migrations'), '#').'/\d{4}_\d{2}_\d{2}_\d{6}_add_two_factor_columns_to_users_table\.php$#',
    );
});

it('runs the published migration against a clean host users table', function () use ($stub): void {
    $directory = sys_get_temp_dir().'/two-factor-publish-'.Str::random(8);
    mkdir($directory);
    copy($stub, $directory.'/2026_01_01_000000_add_two_factor_columns_to_users_table.php');

    config(['database.connections.fresh' => [
        'driver' => 'sqlite',
        'database' => ':memory:',
        'prefix' => '',
    ]]);

    // A host users table with none of the package's columns on it.
    Schema::connection('fresh')->create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('email');
    });

    $this->artisan('migrate', [
        '--database' => 'fresh',
        '--path' => $directory,
        '--realpath' => true,
    ])->assertSuccessful();

    expect(Schema::connection('fresh')->hasColumns('users', [
        'two_factor_secret',
        'two_factor_recovery_codes',
        'two_factor_confirmed_at',
        'two_factor_last_used_timestep',
    ]))->toBeTrue();

    DB::setDefaultConnection('testing');
    array_map(unlink(...), (array) glob($directory.'/*'));
    rmdir($directory);
});
