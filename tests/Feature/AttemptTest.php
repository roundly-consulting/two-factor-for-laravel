<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\TwoFactor\Actions\StartEnrolment;
use RoundlyConsulting\TwoFactor\DataTransferObjects\TwoFactorSetup;
use RoundlyConsulting\TwoFactor\Enums\TwoFactorMethod;
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

    expect(TwoFactor::for($user)->attempt('123456')->verified)->toBeFalse();
});

it('rejects a valid code for an unconfirmed pending enrolment', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    $user = TwoFactorUser::factory()->create();
    $setup = app(StartEnrolment::class)->execute($user);

    // Secret persisted, possession never proven → not a working second factor.
    expect($user->fresh()->hasPendingTwoFactor())->toBeTrue()
        ->and(TwoFactor::for($user->fresh())->attempt(TwoFactor::currentCode($setup->secret))->verified)->toBeFalse();

    Carbon::setTestNow();
});

it('accepts a valid current code once', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    $user = enrolledUser();

    expect(TwoFactor::for($user)->attempt(TwoFactor::currentCode((string) $user->twoFactorSecret()))->verified)->toBeTrue();

    Carbon::setTestNow();
});

it('rejects the same code replayed within its window', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    Event::fake();
    $user = enrolledUser();
    $code = TwoFactor::currentCode((string) $user->twoFactorSecret());

    expect(TwoFactor::for($user)->attempt($code)->verified)->toBeTrue()
        ->and(TwoFactor::for($user->fresh())->attempt($code)->verified)->toBeFalse();
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

    expect(TwoFactor::for($a)->attempt($code)->verified)->toBeTrue()
        ->and(TwoFactor::for($b)->attempt($code)->verified)->toBeFalse();

    Carbon::setTestNow();
});

it('rejects an earlier-timestep code after a later success', function (): void {
    $user = enrolledUser();
    $secret = (string) $user->twoFactorSecret();

    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_600));
    expect(TwoFactor::for($user)->attempt(TwoFactor::currentCode($secret))->verified)->toBeTrue();

    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_400));
    expect(TwoFactor::for($user->fresh())->attempt(TwoFactor::currentCode($secret))->verified)->toBeFalse();

    Carbon::setTestNow();
});

it('falls back to a single-use recovery code', function (): void {
    Event::fake();
    [$user, $setup] = enrolledUserWithSetup();
    $code = $setup->recoveryCodes[0];

    expect(TwoFactor::for($user->fresh())->attempt($code)->verified)->toBeTrue()
        ->and(TwoFactor::for($user->fresh())->attempt($code)->verified)->toBeFalse(); // single use
    Event::assertDispatched(RecoveryCodeConsumed::class);

    expect($user->fresh()->twoFactorRecoveryCodesRemaining())->toBe(7);
});

it('does not double-spend a recovery code across a stale read', function (): void {
    [$user, $setup] = enrolledUserWithSetup();
    $code = $setup->recoveryCodes[0];

    // Request A holds a stale instance; request B consumes the code out of band.
    $stale = TwoFactorUser::find($user->getKey());
    expect(TwoFactor::for(TwoFactorUser::find($user->getKey()))->attempt($code)->verified)->toBeTrue();

    // Request A carrying the same code must fail — consumption re-reads under lock.
    expect(TwoFactor::for($stale)->attempt($code)->verified)->toBeFalse()
        ->and($user->fresh()->twoFactorRecoveryCodesRemaining())->toBe(7);
});

it('dispatches TwoFactorVerified on a successful totp verify', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    Event::fake();
    $user = enrolledUser();

    TwoFactor::for($user)->attempt(TwoFactor::currentCode((string) $user->twoFactorSecret()));

    Event::assertDispatched(
        TwoFactorVerified::class,
        fn (TwoFactorVerified $event): bool => $event->method === TwoFactorMethod::Totp,
    );
    Event::assertNotDispatched(RecoveryCodeConsumed::class);
    Event::assertNotDispatched(TwoFactorVerificationFailed::class);

    Carbon::setTestNow();
});

it('dispatches TwoFactorVerified with the recovery-code method on a recovery success', function (): void {
    Event::fake();
    [$user, $setup] = enrolledUserWithSetup();

    TwoFactor::for($user->fresh())->attempt($setup->recoveryCodes[0]);

    Event::assertDispatched(
        TwoFactorVerified::class,
        fn (TwoFactorVerified $event): bool => $event->method === TwoFactorMethod::RecoveryCode
            && $event->user->is($user),
    );
});

it('dispatches RecoveryCodeConsumed with the count left after each spend', function (): void {
    Event::fake();
    [$user, $setup] = enrolledUserWithSetup();

    TwoFactor::for($user->fresh())->attempt($setup->recoveryCodes[0]);
    TwoFactor::for($user->fresh())->attempt($setup->recoveryCodes[1]);

    Event::assertDispatchedTimes(RecoveryCodeConsumed::class, 2);
    Event::assertDispatched(RecoveryCodeConsumed::class, fn (RecoveryCodeConsumed $event): bool => $event->remaining === 7);
    Event::assertDispatched(RecoveryCodeConsumed::class, fn (RecoveryCodeConsumed $event): bool => $event->remaining === 6);
});

it('counts down to zero as the last recovery code is spent', function (): void {
    Event::fake();
    config(['two-factor.recovery_codes.count' => 1]);
    [$user, $setup] = enrolledUserWithSetup();

    expect(TwoFactor::for($user->fresh())->attempt($setup->recoveryCodes[0]))
        ->verified->toBeTrue()
        ->remainingRecoveryCodes->toBe(0);

    Event::assertDispatched(RecoveryCodeConsumed::class, fn (RecoveryCodeConsumed $event): bool => $event->remaining === 0);

    // With the list exhausted the same code — and any other — now fails.
    expect(TwoFactor::for($user->fresh())->attempt($setup->recoveryCodes[0]))
        ->verified->toBeFalse()
        ->remainingRecoveryCodes->toBe(0);
});

it('dispatches TwoFactorVerificationFailed on a genuine failure', function (): void {
    Event::fake();
    $user = enrolledUser();

    expect(TwoFactor::for($user)->attempt('000000')->verified)->toBeFalse();

    Event::assertDispatched(TwoFactorVerificationFailed::class);
    Event::assertNotDispatched(TwoFactorVerified::class);
});

it('does not dispatch verification events on a replay', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    Event::fake();
    $user = enrolledUser();
    $code = TwoFactor::currentCode((string) $user->twoFactorSecret());

    TwoFactor::for($user)->attempt($code);
    TwoFactor::for($user->fresh())->attempt($code);

    Event::assertDispatched(TwoFactorReplayDetected::class);
    Event::assertDispatchedTimes(TwoFactorVerified::class, 1);
    Event::assertNotDispatched(TwoFactorVerificationFailed::class);

    Carbon::setTestNow();
});

it('does not dispatch verification events when the user has no secret', function (): void {
    Event::fake();
    $user = TwoFactorUser::factory()->create();

    expect(TwoFactor::for($user)->attempt('123456')->verified)->toBeFalse();

    Event::assertNotDispatched(TwoFactorVerified::class);
    Event::assertNotDispatched(TwoFactorVerificationFailed::class);
});

it('accepts recovery codes regardless of the totp replay guard', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    [$user, $setup] = enrolledUserWithSetup();
    $secret = (string) $user->fresh()->twoFactorSecret();

    // Burn a TOTP timestep first, advancing the replay guard.
    TwoFactor::for($user->fresh())->attempt(TwoFactor::currentCode($secret));

    // A recovery code still works after the guard has recorded a timestep.
    expect(TwoFactor::for($user->fresh())->attempt($setup->recoveryCodes[1])->verified)->toBeTrue();

    Carbon::setTestNow();
});

it('locks out and throws after the configured failed attempts', function (): void {
    Event::fake();
    config(['two-factor.attempts' => ['max' => 3, 'decay' => 60]]);
    $user = enrolledUser();

    // Three genuine failures exhaust the budget.
    foreach (range(1, 3) as $ignored) {
        expect(TwoFactor::for($user->fresh())->attempt('000000')->verified)->toBeFalse();
    }

    // The next attempt is locked out before any verification work.
    expect(fn (): bool => TwoFactor::for($user->fresh())->attempt('000000')->verified)
        ->toThrow(TwoFactorRateLimitedException::class);
    Event::assertDispatched(TwoFactorRateLimited::class);
});

it('clears the attempt counter on a successful verify', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    config(['two-factor.attempts' => ['max' => 3, 'decay' => 60]]);
    $user = enrolledUser();
    $secret = (string) $user->twoFactorSecret();

    // Two failures, then a success resets the budget.
    TwoFactor::for($user->fresh())->attempt('000000');
    TwoFactor::for($user->fresh())->attempt('000000');
    expect(TwoFactor::for($user->fresh())->attempt(TwoFactor::currentCode($secret))->verified)->toBeTrue();

    // A fresh run of failures does not immediately lock out.
    expect(TwoFactor::for($user->fresh())->attempt('000000')->verified)->toBeFalse();

    Carbon::setTestNow();
});

it('never rate-limits when the limiter is disabled', function (): void {
    config(['two-factor.attempts' => null]);
    $user = enrolledUser();

    foreach (range(1, 20) as $ignored) {
        expect(TwoFactor::for($user->fresh())->attempt('000000')->verified)->toBeFalse();
    }
});
