<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\TwoFactor\Actions\StartEnrolment;
use RoundlyConsulting\TwoFactor\DataTransferObjects\TwoFactorSetup;
use RoundlyConsulting\TwoFactor\Events\RecoveryCodeConsumed;
use RoundlyConsulting\TwoFactor\Events\TwoFactorRateLimited;
use RoundlyConsulting\TwoFactor\Events\TwoFactorReplayDetected;
use RoundlyConsulting\TwoFactor\Events\TwoFactorVerificationFailed;
use RoundlyConsulting\TwoFactor\Events\TwoFactorVerified;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorRateLimitedException;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;
use RoundlyConsulting\TwoFactor\Tests\Fixtures\TwoFactorUser;

/**
 * A fully enabled user with a clean replay guard: enrolment is started, then
 * confirmed_at is stamped directly so the last-used timestep stays untouched
 * (confirming through the action would spend a timestep the tests rely on).
 */
function enrolledUser(): TwoFactorUser
{
    $user = TwoFactorUser::factory()->create();
    app(StartEnrolment::class)->execute($user);

    $user->setAttribute((string) config('two-factor.columns.confirmed_at'), now());
    $user->save();

    return $user->fresh();
}

/**
 * @return array{0: TwoFactorUser, 1: TwoFactorSetup}
 */
function enrolledUserWithSetup(): array
{
    $user = TwoFactorUser::factory()->create();
    $setup = app(StartEnrolment::class)->execute($user);

    $user->setAttribute((string) config('two-factor.columns.confirmed_at'), now());
    $user->save();

    return [$user->fresh(), $setup];
}

it('returns false for a user without a secret', function (): void {
    $user = TwoFactorUser::factory()->create();

    expect(TwoFactor::verifyFor($user, '123456'))->toBeFalse();
});

it('rejects a valid code for an unconfirmed pending enrolment', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    $user = TwoFactorUser::factory()->create();
    $setup = app(StartEnrolment::class)->execute($user);

    // Secret persisted, possession never proven → not a working second factor.
    expect($user->fresh()->hasPendingTwoFactor())->toBeTrue()
        ->and(TwoFactor::verifyFor($user->fresh(), TwoFactor::currentCode($setup->secret)))->toBeFalse();

    Carbon::setTestNow();
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

it('rejects a concurrent replay across two stale reads of the same row', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    $user = enrolledUser();
    $secret = (string) $user->twoFactorSecret();
    $code = TwoFactor::currentCode($secret);

    // Both requests loaded the row before either recorded the timestep.
    $a = TwoFactorUser::find($user->getKey());
    $b = TwoFactorUser::find($user->getKey());

    expect(TwoFactor::verifyFor($a, $code))->toBeTrue()
        ->and(TwoFactor::verifyFor($b, $code))->toBeFalse();

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
    [$user, $setup] = enrolledUserWithSetup();
    $code = $setup->recoveryCodes[0];

    expect(TwoFactor::verifyFor($user->fresh(), $code))->toBeTrue()
        ->and(TwoFactor::verifyFor($user->fresh(), $code))->toBeFalse(); // single use
    Event::assertDispatched(RecoveryCodeConsumed::class);

    expect($user->fresh()->twoFactorRecoveryCodesRemaining())->toBe(7);
});

it('does not double-spend a recovery code across a stale read', function (): void {
    [$user, $setup] = enrolledUserWithSetup();
    $code = $setup->recoveryCodes[0];

    // Request A holds a stale instance; request B consumes the code out of band.
    $stale = TwoFactorUser::find($user->getKey());
    expect(TwoFactor::verifyFor(TwoFactorUser::find($user->getKey()), $code))->toBeTrue();

    // Request A carrying the same code must fail — consumption re-reads under lock.
    expect(TwoFactor::verifyFor($stale, $code))->toBeFalse()
        ->and($user->fresh()->twoFactorRecoveryCodesRemaining())->toBe(7);
});

it('dispatches TwoFactorVerified on a successful totp verify', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    Event::fake();
    $user = enrolledUser();

    TwoFactor::verifyFor($user, TwoFactor::currentCode((string) $user->twoFactorSecret()));

    Event::assertDispatched(
        TwoFactorVerified::class,
        fn (TwoFactorVerified $event): bool => $event->viaRecoveryCode === false,
    );
    Event::assertNotDispatched(TwoFactorVerificationFailed::class);

    Carbon::setTestNow();
});

it('dispatches TwoFactorVerified with the recovery flag on a recovery success', function (): void {
    Event::fake();
    [$user, $setup] = enrolledUserWithSetup();

    TwoFactor::verifyFor($user->fresh(), $setup->recoveryCodes[0]);

    Event::assertDispatched(
        TwoFactorVerified::class,
        fn (TwoFactorVerified $event): bool => $event->viaRecoveryCode === true,
    );
});

it('dispatches TwoFactorVerificationFailed on a genuine failure', function (): void {
    Event::fake();
    $user = enrolledUser();

    expect(TwoFactor::verifyFor($user, '000000'))->toBeFalse();

    Event::assertDispatched(TwoFactorVerificationFailed::class);
    Event::assertNotDispatched(TwoFactorVerified::class);
});

it('does not dispatch verification events on a replay', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    Event::fake();
    $user = enrolledUser();
    $code = TwoFactor::currentCode((string) $user->twoFactorSecret());

    TwoFactor::verifyFor($user, $code);
    TwoFactor::verifyFor($user->fresh(), $code);

    Event::assertDispatched(TwoFactorReplayDetected::class);
    Event::assertDispatchedTimes(TwoFactorVerified::class, 1);
    Event::assertNotDispatched(TwoFactorVerificationFailed::class);

    Carbon::setTestNow();
});

it('does not dispatch verification events when the user has no secret', function (): void {
    Event::fake();
    $user = TwoFactorUser::factory()->create();

    expect(TwoFactor::verifyFor($user, '123456'))->toBeFalse();

    Event::assertNotDispatched(TwoFactorVerified::class);
    Event::assertNotDispatched(TwoFactorVerificationFailed::class);
});

it('accepts recovery codes regardless of the totp replay guard', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    [$user, $setup] = enrolledUserWithSetup();
    $secret = (string) $user->fresh()->twoFactorSecret();

    // Burn a TOTP timestep first, advancing the replay guard.
    TwoFactor::verifyFor($user->fresh(), TwoFactor::currentCode($secret));

    // A recovery code still works after the guard has recorded a timestep.
    expect(TwoFactor::verifyFor($user->fresh(), $setup->recoveryCodes[1]))->toBeTrue();

    Carbon::setTestNow();
});

it('locks out and throws after the configured failed attempts', function (): void {
    Event::fake();
    config(['two-factor.attempts' => ['max' => 3, 'decay' => 60]]);
    $user = enrolledUser();

    // Three genuine failures exhaust the budget.
    foreach (range(1, 3) as $ignored) {
        expect(TwoFactor::verifyFor($user->fresh(), '000000'))->toBeFalse();
    }

    // The next attempt is locked out before any verification work.
    expect(fn (): bool => TwoFactor::verifyFor($user->fresh(), '000000'))
        ->toThrow(TwoFactorRateLimitedException::class);
    Event::assertDispatched(TwoFactorRateLimited::class);
});

it('clears the attempt counter on a successful verify', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    config(['two-factor.attempts' => ['max' => 3, 'decay' => 60]]);
    $user = enrolledUser();
    $secret = (string) $user->twoFactorSecret();

    // Two failures, then a success resets the budget.
    TwoFactor::verifyFor($user->fresh(), '000000');
    TwoFactor::verifyFor($user->fresh(), '000000');
    expect(TwoFactor::verifyFor($user->fresh(), TwoFactor::currentCode($secret)))->toBeTrue();

    // A fresh run of failures does not immediately lock out.
    expect(TwoFactor::verifyFor($user->fresh(), '000000'))->toBeFalse();

    Carbon::setTestNow();
});

it('never rate-limits when the limiter is disabled', function (): void {
    config(['two-factor.attempts' => null]);
    $user = enrolledUser();

    foreach (range(1, 20) as $ignored) {
        expect(TwoFactor::verifyFor($user->fresh(), '000000'))->toBeFalse();
    }
});
