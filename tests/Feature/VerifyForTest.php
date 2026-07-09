<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\TwoFactor\Actions\StartEnrolment;
use RoundlyConsulting\TwoFactor\Events\RecoveryCodeConsumed;
use RoundlyConsulting\TwoFactor\Events\TwoFactorReplayDetected;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;
use RoundlyConsulting\TwoFactor\Tests\Fixtures\TwoFactorUser;

function enrolledUser(): TwoFactorUser
{
    $user = TwoFactorUser::factory()->create();
    app(StartEnrolment::class)->execute($user);

    return $user->fresh();
}

it('returns false for a user without a secret', function (): void {
    $user = TwoFactorUser::factory()->create();

    expect(TwoFactor::verifyFor($user, '123456'))->toBeFalse();
});

it('accepts a valid current code once', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    $user = enrolledUser();

    expect(TwoFactor::verifyFor($user, TwoFactor::currentCode((string) $user->twoFactorSecret())))->toBeTrue();

    Carbon::setTestNow();
});

it('rejects the same code replayed within its window', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    Event::fake();
    $user = enrolledUser();
    $code = TwoFactor::currentCode((string) $user->twoFactorSecret());

    expect(TwoFactor::verifyFor($user, $code))->toBeTrue()
        ->and(TwoFactor::verifyFor($user->fresh(), $code))->toBeFalse();
    Event::assertDispatched(TwoFactorReplayDetected::class);

    Carbon::setTestNow();
});

it('rejects an earlier-timestep code after a later success', function (): void {
    $user = enrolledUser();
    $secret = (string) $user->twoFactorSecret();

    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_600));
    expect(TwoFactor::verifyFor($user, TwoFactor::currentCode($secret)))->toBeTrue();

    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_400));
    expect(TwoFactor::verifyFor($user->fresh(), TwoFactor::currentCode($secret)))->toBeFalse();

    Carbon::setTestNow();
});

it('falls back to a single-use recovery code', function (): void {
    Event::fake();
    $user = TwoFactorUser::factory()->create();
    $setup = app(StartEnrolment::class)->execute($user);
    $code = $setup->recoveryCodes[0];

    expect(TwoFactor::verifyFor($user->fresh(), $code))->toBeTrue()
        ->and(TwoFactor::verifyFor($user->fresh(), $code))->toBeFalse(); // single use
    Event::assertDispatched(RecoveryCodeConsumed::class);

    expect($user->fresh()->twoFactorRecoveryCodes())->toHaveCount(7);
});

it('accepts recovery codes regardless of the totp replay guard', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    $user = TwoFactorUser::factory()->create();
    $setup = app(StartEnrolment::class)->execute($user);
    $secret = (string) $user->fresh()->twoFactorSecret();

    // Burn a TOTP timestep first, advancing the replay guard.
    TwoFactor::verifyFor($user->fresh(), TwoFactor::currentCode($secret));

    // A recovery code still works after the guard has recorded a timestep.
    expect(TwoFactor::verifyFor($user->fresh(), $setup->recoveryCodes[1]))->toBeTrue();

    Carbon::setTestNow();
});
