<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use RoundlyConsulting\TwoFactor\Actions\StartEnrolment;
use RoundlyConsulting\TwoFactor\DataTransferObjects\TwoFactorSetup;
use RoundlyConsulting\TwoFactor\Enums\TwoFactorMethod;
use RoundlyConsulting\TwoFactor\Events\RecoveryCodeConsumed;
use RoundlyConsulting\TwoFactor\Events\TwoFactorReplayDetected;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorRateLimitedException;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;
use RoundlyConsulting\TwoFactor\Tests\Fixtures\TwoFactorUser;

/**
 * The 2FA challenge is a security boundary, so its two mutable pieces of state —
 * the single-use recovery-code list and the failed-attempt counter — must be
 * safe under concurrency. A lost update here means a recovery code spent twice
 * (two sessions authenticated by one code) or a brute-force counter that fails
 * to lock an attacker out.
 *
 * These pins deliberately do not depend on the emitted SQL: SQLite compiles
 * `lockForUpdate()` to an empty string, so the lock is invisible on the wire.
 */

/**
 * @return array{0: TwoFactorUser, 1: TwoFactorSetup}
 */
function racingUser(): array
{
    $user = TwoFactorUser::factory()->create();
    $setup = app(StartEnrolment::class)->execute($user);

    $user->setAttribute((string) config('two-factor.columns.confirmed_at'), now());
    $user->save();

    /** @var TwoFactorUser $fresh */
    $fresh = $user->fresh();

    return [$fresh, $setup];
}

/**
 * The lock is taken even for a candidate that matches nothing: the guard runs *inside*
 * the critical section, never on a stale pre-lock read.
 *
 * The lock's shape and depth are pinned in RecoveryCodeLockShapeTest, which uses the
 * testing package's recording grammar (variant B) — it observes the emitted SQL rather
 * than the builder call, so it can also see whether the statement is one a real engine
 * accepts. That is the distinction the deleted local fixture could not make, and it is
 * how credits shipped a `FOR UPDATE` on an aggregate under a green lock-recording suite.
 */
it('takes the lock even when the candidate code matches nothing', function (): void {
    [$user, $setup] = racingUser();

    $depths = [];
    DB::listen(function ($query) use (&$depths): void {
        if (str_contains(strtolower($query->sql), 'for update') || $query->connection->transactionLevel() > 0) {
            $depths[] = $query->connection->transactionLevel();
        }
    });

    expect(TwoFactor::verifyFor($user, 'AAAAA-BBBBB'))->toBeFalse()
        // The consume transaction opened, so the miss was decided under the lock.
        ->and($depths)->not->toBeEmpty()
        ->and(max($depths))->toBe(1);

    expect(TwoFactor::verifyFor($user, $setup->recoveryCodes[0]))->toBeTrue();
});

it('never lets two racing verifications spend the same recovery code twice', function (): void {
    // Faked before the service resolves: it captures the dispatcher on construction.
    Event::fake([RecoveryCodeConsumed::class]);

    [$user, $setup] = racingUser();
    $code = $setup->recoveryCodes[0];

    // Two requests that both loaded the user *before* either consumed anything:
    // each holds the same stale in-memory recovery-code list.
    /** @var TwoFactorUser $requestA */
    $requestA = TwoFactorUser::query()->findOrFail($user->getKey());
    /** @var TwoFactorUser $requestB */
    $requestB = TwoFactorUser::query()->findOrFail($user->getKey());

    expect($requestA->twoFactorRecoveryCodes())->toHaveCount(8)
        ->and($requestB->twoFactorRecoveryCodes())->toHaveCount(8);

    expect(TwoFactor::verifyFor($requestA, $code))->toBeTrue()
        ->and(TwoFactor::verifyFor($requestB, $code))->toBeFalse();

    // Exactly one spend: the second request re-read the list under the lock and
    // found the code already gone.
    expect($user->fresh()?->twoFactorRecoveryCodes())->toHaveCount(7);

    Event::assertDispatchedTimes(RecoveryCodeConsumed::class, 1);
});

it('does not clobber a write that lands between the locked read and the recovery-code write', function (): void {
    [$user, $setup] = racingUser();

    $raced = false;

    // Fires when the locked row is hydrated — i.e. inside the critical section,
    // after the lock, before the write. Stand-in for a competing request that
    // commits a different column while the challenge holds the row.
    Event::listen('eloquent.retrieved: '.TwoFactorUser::class, function () use (&$raced, $user): void {
        if ($raced || DB::transactionLevel() === 0) {
            return;
        }

        $raced = true;

        TwoFactorUser::query()->whereKey($user->getKey())->toBase()->update(['name' => 'raced']);
    });

    expect(TwoFactor::verifyFor($user, $setup->recoveryCodes[0]))->toBeTrue()
        ->and($raced)->toBeTrue();

    $fresh = $user->fresh();

    // The consumption wrote only its own column, so the competing write survives.
    expect($fresh?->getAttribute('name'))->toBe('raced')
        ->and($fresh?->twoFactorRecoveryCodes())->toHaveCount(7);
});

it('fails closed when the user row disappears before the locked read', function (): void {
    [$user, $setup] = racingUser();

    // A competing request deletes the account while the challenge is in flight.
    TwoFactorUser::query()->whereKey($user->getKey())->delete();

    // A vanished row is a failed verification, not an unhandled exception in the
    // middle of someone's login.
    expect(TwoFactor::verifyFor($user, $setup->recoveryCodes[0]))->toBeFalse();
});

it('spends a recovery code without bumping the host row timestamps', function (): void {
    [$user, $setup] = racingUser();

    $updatedAt = $user->getAttribute('updated_at');

    Carbon::setTestNow(now()->addHour());

    expect(TwoFactor::verifyFor($user, $setup->recoveryCodes[0]))->toBeTrue();

    // The write is scoped to the recovery-code column: consuming a code is not a
    // profile update, and must not race the host's own updated_at bookkeeping.
    expect($user->fresh()?->getAttribute('updated_at')?->toDateTimeString())
        ->toBe($updatedAt?->toDateTimeString());

    Carbon::setTestNow();
});

it('never loses a failed attempt that races with another request', function (): void {
    config(['two-factor.attempts' => ['max' => 5, 'decay' => 60]]);

    [$user] = racingUser();
    $key = 'two-factor:'.$user::class.':'.$user->getKey();

    // A competing request records its failure first...
    RateLimiter::hit($key, 60);

    // ...and ours must fold into it, not overwrite a value read before it landed.
    expect(TwoFactor::verifyFor($user, '000000'))->toBeFalse()
        ->and(RateLimiter::attempts($key))->toBe(2);

    RateLimiter::hit($key, 60);

    expect(TwoFactor::verifyFor($user, '000000'))->toBeFalse()
        ->and(RateLimiter::attempts($key))->toBe(4);
});

it('locks the challenge out at the configured maximum even under interleaved failures', function (): void {
    config(['two-factor.attempts' => ['max' => 3, 'decay' => 60]]);

    [$user] = racingUser();
    $key = 'two-factor:'.$user::class.':'.$user->getKey();

    // Two of our own failures interleaved with one from a competing request.
    expect(TwoFactor::verifyFor($user, '000000'))->toBeFalse();
    RateLimiter::hit($key, 60);
    expect(TwoFactor::verifyFor($user, '000000'))->toBeFalse();

    expect(RateLimiter::attempts($key))->toBe(3);

    // The competing failure counts: the attacker is locked out at 3, not 4.
    TwoFactor::verifyFor($user, '000000');
})->throws(TwoFactorRateLimitedException::class);

it('lets only one of two racing submissions of the same totp code through', function (): void {
    Event::fake([TwoFactorReplayDetected::class]);

    [$user, $setup] = racingUser();
    $code = TwoFactor::currentCode($setup->secret);

    /** @var TwoFactorUser $requestA */
    $requestA = TwoFactorUser::query()->findOrFail($user->getKey());
    /** @var TwoFactorUser $requestB */
    $requestB = TwoFactorUser::query()->findOrFail($user->getKey());

    // Both hold a stale (null) last-used timestep; the guard's conditional
    // UPDATE is the compare-and-set, so exactly one claim affects a row.
    expect(TwoFactor::verifyFor($requestA, $code))->toBeTrue()
        ->and(TwoFactor::verifyFor($requestB, $code))->toBeFalse();

    Event::assertDispatchedTimes(TwoFactorReplayDetected::class, 1);
});

it('reports the locked row count, not the stale instance, to a racing attempt', function (): void {
    [$user, $setup] = racingUser();

    /** @var TwoFactorUser $requestA */
    $requestA = TwoFactorUser::query()->findOrFail($user->getKey());
    /** @var TwoFactorUser $requestB */
    $requestB = TwoFactorUser::query()->findOrFail($user->getKey());

    expect(TwoFactor::attempt($requestA, $setup->recoveryCodes[0]))
        ->verified->toBeTrue()
        ->method->toBe(TwoFactorMethod::RecoveryCode)
        ->remainingRecoveryCodes->toBe(7);

    // B still holds eight codes in memory; the count it is told comes from the
    // row it re-read under the lock, where A's spend has already landed.
    expect($requestB->twoFactorRecoveryCodes())->toHaveCount(8);

    expect(TwoFactor::attempt($requestB, $setup->recoveryCodes[0]))
        ->verified->toBeFalse()
        ->remainingRecoveryCodes->toBe(7);

    expect(TwoFactor::attempt($requestB, $setup->recoveryCodes[1]))
        ->verified->toBeTrue()
        ->remainingRecoveryCodes->toBe(6);
});

it('reports the losing racer of a totp code as replayed', function (): void {
    [$user, $setup] = racingUser();
    $code = TwoFactor::currentCode($setup->secret);

    /** @var TwoFactorUser $requestA */
    $requestA = TwoFactorUser::query()->findOrFail($user->getKey());
    /** @var TwoFactorUser $requestB */
    $requestB = TwoFactorUser::query()->findOrFail($user->getKey());

    expect(TwoFactor::attempt($requestA, $code))
        ->verified->toBeTrue()
        ->method->toBe(TwoFactorMethod::Totp);

    expect(TwoFactor::attempt($requestB, $code))
        ->verified->toBeFalse()
        ->replayed->toBeTrue();
});

it('reports zero remaining when the row vanished before the locked read', function (): void {
    [$user, $setup] = racingUser();

    TwoFactorUser::query()->whereKey($user->getKey())->delete();

    expect(TwoFactor::attempt($user, $setup->recoveryCodes[0]))
        ->verified->toBeFalse()
        ->remainingRecoveryCodes->toBe(0);
});
