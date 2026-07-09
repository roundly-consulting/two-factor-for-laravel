<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\TwoFactor\Contracts\ReplayGuard;
use RoundlyConsulting\TwoFactor\ReplayGuards\CacheReplayGuard;

it('adds and drops all four two-factor columns via the blueprint macros', function (): void {
    Schema::create('accounts', function ($table): void {
        $table->id();
        $table->twoFactorColumns();
    });

    expect(Schema::hasColumns('accounts', [
        'two_factor_secret',
        'two_factor_recovery_codes',
        'two_factor_confirmed_at',
        'two_factor_last_used_timestep',
    ]))->toBeTrue();

    Schema::table('accounts', function ($table): void {
        $table->dropTwoFactorColumns();
    });

    expect(Schema::hasColumn('accounts', 'two_factor_secret'))->toBeFalse()
        ->and(Schema::hasColumn('accounts', 'two_factor_last_used_timestep'))->toBeFalse();
});

it('resolves a cache guard bound to the configured store', function (): void {
    config([
        'two-factor.replay_guard' => 'cache',
        'two-factor.cache.store' => 'array',
    ]);
    app()->forgetInstance(ReplayGuard::class);

    expect(app(ReplayGuard::class))->toBeInstanceOf(CacheReplayGuard::class);
});
