<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\TwoFactor\Actions\ConfirmEnrolment;
use RoundlyConsulting\TwoFactor\Actions\DisableTwoFactor;
use RoundlyConsulting\TwoFactor\Actions\RegenerateRecoveryCodes;
use RoundlyConsulting\TwoFactor\Actions\StartEnrolment;
use RoundlyConsulting\TwoFactor\DataTransferObjects\TwoFactorSetup;
use RoundlyConsulting\TwoFactor\Events\RecoveryCodesRegenerated;
use RoundlyConsulting\TwoFactor\Events\TwoFactorConfirmed;
use RoundlyConsulting\TwoFactor\Events\TwoFactorDisabled;
use RoundlyConsulting\TwoFactor\Events\TwoFactorEnrolmentStarted;
use RoundlyConsulting\TwoFactor\Events\TwoFactorReplayDetected;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorCodeException;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorAlreadyEnabledException;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorNotPendingException;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;
use RoundlyConsulting\TwoFactor\Tests\Fixtures\TwoFactorUser;

it('runs the full enrol, confirm, disable happy path', function (): void {
    Event::fake();
    $user = TwoFactorUser::factory()->create();

    $setup = app(StartEnrolment::class)->execute($user);

    expect($setup)->toBeInstanceOf(TwoFactorSetup::class)
        ->and($setup->recoveryCodes)->toHaveCount(8)
        ->and($setup->provisioningUri)->toContain('otpauth://')
        ->and($user->fresh()->hasPendingTwoFactor())->toBeTrue();
    Event::assertDispatched(TwoFactorEnrolmentStarted::class);

    app(ConfirmEnrolment::class)->execute($user, TwoFactor::currentCode($setup->secret));

    expect($user->fresh()->hasTwoFactorEnabled())->toBeTrue();
    Event::assertDispatched(TwoFactorConfirmed::class);

    app(DisableTwoFactor::class)->execute($user);

    $fresh = $user->fresh();
    expect($fresh->hasTwoFactorEnabled())->toBeFalse()
        ->and($fresh->twoFactorSecret())->toBeNull()
        ->and($fresh->twoFactorRecoveryCodes())->toBe([]);
    Event::assertDispatched(TwoFactorDisabled::class);
});

it('confirms an enrolment started with a secret length base32 cannot end on', function (int $length): void {
    config(['two-factor.secret_length' => $length]);
    $user = TwoFactorUser::factory()->create();

    $setup = TwoFactor::for($user)->start();
    TwoFactor::for($user)->confirm(TwoFactor::currentCode($setup->secret));

    expect($user->fresh()->hasTwoFactorEnabled())->toBeTrue()
        ->and($setup->secret)->toHaveLength($length + 1);
})->with([17, 19, 22, 25, 30]);

it('encrypts the stored secret at rest', function (): void {
    $user = TwoFactorUser::factory()->create();
    $setup = app(StartEnrolment::class)->execute($user);

    $raw = $user->fresh()->getRawOriginal('two_factor_secret');

    expect($raw)->not->toBe($setup->secret)
        ->and(decrypt($raw, false))->toBe($setup->secret);
});

it('rejects starting enrolment when already enabled', function (): void {
    $user = TwoFactorUser::factory()->create();
    $setup = app(StartEnrolment::class)->execute($user);
    app(ConfirmEnrolment::class)->execute($user, TwoFactor::currentCode($setup->secret));

    app(StartEnrolment::class)->execute($user->fresh());
})->throws(TwoFactorAlreadyEnabledException::class);

it('regenerates secret and codes when re-enrolling while pending', function (): void {
    $user = TwoFactorUser::factory()->create();
    $first = app(StartEnrolment::class)->execute($user);
    $second = app(StartEnrolment::class)->execute($user->fresh());

    expect($second->secret)->not->toBe($first->secret)
        ->and($second->recoveryCodes)->not->toBe($first->recoveryCodes);
});

it('throws when confirming with no pending enrolment', function (): void {
    $user = TwoFactorUser::factory()->create();

    app(ConfirmEnrolment::class)->execute($user, '123456');
})->throws(TwoFactorNotPendingException::class);

it('throws on an invalid confirmation code', function (): void {
    $user = TwoFactorUser::factory()->create();
    app(StartEnrolment::class)->execute($user);

    app(ConfirmEnrolment::class)->execute($user->fresh(), '000000');
})->throws(InvalidTwoFactorCodeException::class);

/**
 * Confirming is only ever a transition from pending to enabled. A confirm on an
 * already-enabled user used to return silently WITHOUT checking the code, so a caller
 * treating a clean return as proof of possession (a forced-enrolment login step, an
 * account "confirm" endpoint) accepted any code at all. Nothing is pending, so it is
 * refused — whatever the code — and nothing is written or dispatched.
 */
it('refuses to confirm an already-enabled user, whatever the code', function (string $which): void {
    $user = TwoFactorUser::factory()->create();
    $setup = app(StartEnrolment::class)->execute($user);

    Carbon::setTestNow(Carbon::now()->subSeconds(90));
    app(ConfirmEnrolment::class)->execute($user, TwoFactor::currentCode($setup->secret));
    Carbon::setTestNow();

    $before = $user->fresh();
    Event::fake();

    $code = $which === 'valid' ? TwoFactor::currentCode($setup->secret) : '000000';

    expect(fn () => app(ConfirmEnrolment::class)->execute($user->fresh(), $code))
        ->toThrow(TwoFactorNotPendingException::class, 'already enabled');

    $after = $user->fresh();

    expect($after->hasTwoFactorEnabled())->toBeTrue()
        ->and($after->two_factor_confirmed_at->equalTo($before->two_factor_confirmed_at))->toBeTrue()
        ->and($after->two_factor_last_used_timestep)->toBe($before->two_factor_last_used_timestep);

    Event::assertNotDispatched(TwoFactorConfirmed::class);
})->with(['wrong code' => ['wrong'], 'valid current code' => ['valid']]);

it('refuses a re-confirm through the trait verb too', function (): void {
    $user = TwoFactorUser::factory()->create();
    $setup = $user->startTwoFactorEnrolment();
    $user->confirmTwoFactor(TwoFactor::currentCode($setup->secret));

    $user->fresh()->confirmTwoFactor('000000');
})->throws(TwoFactorNotPendingException::class);

it('regenerates recovery codes and dispatches an event', function (): void {
    Event::fake();
    $user = TwoFactorUser::factory()->create();
    $setup = app(StartEnrolment::class)->execute($user);

    $codes = app(RegenerateRecoveryCodes::class)->execute($user);

    // Codes are hashed at rest by default, so the stored list is not the plaintext.
    expect($codes)->toHaveCount(8)
        ->and($codes)->not->toBe($setup->recoveryCodes)
        ->and($user->fresh()->twoFactorRecoveryCodesRemaining())->toBe(8)
        ->and($user->fresh()->twoFactorRecoveryCodes())->not->toBe($codes);
    Event::assertDispatched(RecoveryCodesRegenerated::class);
});

it('rejects the confirmation code replayed at first login', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    Event::fake();
    $user = TwoFactorUser::factory()->create();
    $setup = app(StartEnrolment::class)->execute($user);
    $code = TwoFactor::currentCode($setup->secret);

    app(ConfirmEnrolment::class)->execute($user->fresh(), $code);

    // The exact code used to confirm cannot double as the first login code.
    expect(TwoFactor::for($user->fresh())->attempt($code)->verified)->toBeFalse();
    Event::assertDispatched(TwoFactorReplayDetected::class);

    Carbon::setTestNow();
});

it('accepts a later-step code after confirmation', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    $user = TwoFactorUser::factory()->create();
    $setup = app(StartEnrolment::class)->execute($user);

    app(ConfirmEnrolment::class)->execute($user->fresh(), TwoFactor::currentCode($setup->secret));

    // A code at the next timestep still verifies.
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_060));
    expect(TwoFactor::for($user->fresh())->attempt(TwoFactor::currentCode($setup->secret))->verified)->toBeTrue();

    Carbon::setTestNow();
});

it('uses a custom column map when configured', function (): void {
    config(['two-factor.columns' => [
        'secret' => 'mfa_secret',
        'recovery_codes' => 'mfa_codes',
        'confirmed_at' => 'mfa_confirmed_at',
        'last_used_timestep' => 'mfa_last_step',
    ]]);

    Schema::table('users', function ($table): void {
        $table->twoFactorColumns();
    });

    $user = TwoFactorUser::factory()->create();
    $setup = app(StartEnrolment::class)->execute($user);

    expect($user->fresh()->getAttribute('mfa_secret'))->not->toBeNull()
        ->and($user->fresh()->twoFactorSecret())->toBe($setup->secret);
});
