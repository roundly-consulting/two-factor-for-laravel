<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\Contracts\ReplayGuard;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorConfigException;
use RoundlyConsulting\TwoFactor\ReplayGuards\CacheReplayGuard;
use RoundlyConsulting\TwoFactor\ReplayGuards\ColumnReplayGuard;
use RoundlyConsulting\TwoFactor\ReplayGuards\NullReplayGuard;
use RoundlyConsulting\TwoFactor\Tests\Fixtures\TwoFactorUser;

it('resolves the column guard by default', function (): void {
    expect(app(ReplayGuard::class))->toBeInstanceOf(ColumnReplayGuard::class);
});

it('resolves the configured guard implementation', function (?string $mode, string $class): void {
    config(['two-factor.replay_guard' => $mode]);
    app()->forgetInstance(ReplayGuard::class);

    expect(app(ReplayGuard::class))->toBeInstanceOf($class);
})->with([
    'column' => ['column', ColumnReplayGuard::class],
    'cache' => ['cache', CacheReplayGuard::class],
    'null' => [null, NullReplayGuard::class],
]);

it('throws on an invalid guard mode', function (): void {
    config(['two-factor.replay_guard' => 'bogus']);
    app()->forgetInstance(ReplayGuard::class);

    app(ReplayGuard::class);
})->throws(InvalidTwoFactorConfigException::class);

it('records and rejects timesteps with the column guard', function (): void {
    $guard = new ColumnReplayGuard;
    $user = TwoFactorUser::factory()->create();

    expect($guard->latestTimestep($user))->toBeNull()
        ->and($guard->reject($user, 100))->toBeFalse(); // ungated until first record

    $guard->record($user, 100);

    expect($guard->latestTimestep($user->fresh()))->toBe(100)
        ->and($guard->reject($user->fresh(), 100))->toBeTrue()  // equal → replay
        ->and($guard->reject($user->fresh(), 99))->toBeTrue()   // earlier → replay
        ->and($guard->reject($user->fresh(), 101))->toBeFalse(); // later → ok
});

it('persists across instances with the cache guard', function (): void {
    $user = TwoFactorUser::factory()->create();

    $first = app()->make(CacheReplayGuard::class, ['store' => null, 'ttl' => 3600]);
    $first->record($user, 200);

    $second = app()->make(CacheReplayGuard::class, ['store' => null, 'ttl' => 3600]);

    expect($second->latestTimestep($user))->toBe(200)
        ->and($second->reject($user, 200))->toBeTrue()
        ->and($second->reject($user, 201))->toBeFalse();
});

it('never rejects with the null guard', function (): void {
    $guard = new NullReplayGuard;
    $user = TwoFactorUser::factory()->create();

    $guard->record($user, 500);

    expect($guard->latestTimestep($user))->toBeNull()
        ->and($guard->reject($user, 1))->toBeFalse()
        ->and($guard->reject($user, 999999))->toBeFalse();
});
