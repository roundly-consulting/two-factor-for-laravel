<?php

declare(strict_types=1);

use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use RoundlyConsulting\TwoFactor\Actions\StartEnrolment;
use RoundlyConsulting\TwoFactor\DataTransferObjects\TwoFactorSetup;
use RoundlyConsulting\TwoFactor\Enums\RecoveryCodeStorage;
use RoundlyConsulting\TwoFactor\Enums\TwoFactorMethod;
use RoundlyConsulting\TwoFactor\Events\RecoveryCodeConsumed;
use RoundlyConsulting\TwoFactor\Events\TwoFactorRateLimited;
use RoundlyConsulting\TwoFactor\Events\TwoFactorReplayDetected;
use RoundlyConsulting\TwoFactor\Events\TwoFactorVerificationFailed;
use RoundlyConsulting\TwoFactor\Events\TwoFactorVerified;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorRateLimitedException;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;
use RoundlyConsulting\TwoFactor\Support\RecoveryCodeManager;
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

it('accepts a recovery code typed in lowercase without its dash, once', function (): void {
    [$user, $setup] = enrolledUserWithSetup();
    $code = $setup->recoveryCodes[0];
    $typed = strtolower(str_replace('-', '', $code));

    expect(TwoFactor::for($user->fresh())->attempt($typed))
        ->verified->toBeTrue()
        ->method->toBe(TwoFactorMethod::RecoveryCode)
        ->remainingRecoveryCodes->toBe(7);

    // Normalising the input changes nothing about single use.
    expect(TwoFactor::for($user->fresh())->attempt($code)->verified)->toBeFalse();
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

/**
 * In hashed mode, matching a candidate is one Hash::check per stored code — about half a
 * second of bcrypt for eight codes. That work must not run while the user row is locked:
 * every mistyped TOTP reaches the recovery fallback, so it would hold the row for every
 * wrong guess. The lock is still taken (VerificationConcurrencyTest pins that); only the
 * single matched entry is re-confirmed under it, by string identity.
 */
it('never runs a recovery-code hash check while holding the row lock', function (string $which): void {
    [$user, $setup] = enrolledUserWithSetup();

    $counting = new class(app('hash')) implements Hasher
    {
        public int $checks = 0;

        public int $checksUnderLock = 0;

        public function __construct(private readonly Hasher $inner) {}

        public function info($hashedValue): array
        {
            return $this->inner->info($hashedValue);
        }

        public function make(#[SensitiveParameter] $value, array $options = []): string
        {
            return $this->inner->make($value, $options);
        }

        public function check(#[SensitiveParameter] $value, $hashedValue, array $options = []): bool
        {
            $this->checks++;

            if (DB::transactionLevel() > 0) {
                $this->checksUnderLock++;
            }

            return $this->inner->check($value, $hashedValue, $options);
        }

        public function needsRehash($hashedValue, array $options = []): bool
        {
            return $this->inner->needsRehash($hashedValue, $options);
        }
    };

    Hash::swap($counting);

    $code = $which === 'right' ? $setup->recoveryCodes[3] : '000000';

    expect(TwoFactor::for($user)->attempt($code)->verified)->toBe($which === 'right')
        // Not vacuous: the candidate really was hash-checked...
        ->and($counting->checks)->toBeGreaterThan(0)
        // ...just never under the lock.
        ->and($counting->checksUnderLock)->toBe(0)
        ->and($user->fresh()?->twoFactorRecoveryCodes())->toHaveCount($which === 'right' ? 7 : 8);
})->with(['wrong code' => ['wrong'], 'right recovery code' => ['right']]);

/**
 * The other half of matching before the lock: a rival request spends the very code this
 * attempt just matched, between the unlocked match and the locked re-read. Under the lock
 * the matched entry is gone, so this attempt fails — one code, one spend.
 */
it('fails closed when a rival spends the matched recovery code before the lock', function (): void {
    Event::fake([RecoveryCodeConsumed::class]);
    [$user, $setup] = enrolledUserWithSetup();
    $code = $setup->recoveryCodes[2];
    $raced = false;

    // Fires on the unlocked match read — outside any transaction, after the match.
    Event::listen('eloquent.retrieved: '.TwoFactorUser::class, function (TwoFactorUser $row) use (&$raced, $code): void {
        if ($raced || DB::transactionLevel() > 0) {
            return;
        }

        $raced = true;

        $rival = TwoFactorUser::query()->findOrFail($row->getKey());
        $rival->timestamps = false;
        $rival->setAttribute(
            (string) config('two-factor.columns.recovery_codes'),
            (new RecoveryCodeManager(RecoveryCodeStorage::Hashed))->consume($rival->twoFactorRecoveryCodes(), $code),
        );
        $rival->save();
    });

    expect(TwoFactor::for($user)->attempt($code))
        ->verified->toBeFalse()
        ->remainingRecoveryCodes->toBe(7)
        ->and($raced)->toBeTrue()
        // Only the rival's spend landed.
        ->and($user->fresh()?->twoFactorRecoveryCodes())->toHaveCount(7);

    Event::assertNotDispatched(RecoveryCodeConsumed::class);
});
