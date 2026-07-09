<?php

declare(strict_types=1);

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

it('is idempotent when confirming an already-enabled user', function (): void {
    $user = TwoFactorUser::factory()->create();
    $setup = app(StartEnrolment::class)->execute($user);
    app(ConfirmEnrolment::class)->execute($user, TwoFactor::currentCode($setup->secret));

    $confirmedAt = $user->fresh()->two_factor_confirmed_at;

    // Re-confirming with a wrong code is a no-op, not an error.
    app(ConfirmEnrolment::class)->execute($user->fresh(), '000000');

    expect($user->fresh()->hasTwoFactorEnabled())->toBeTrue()
        ->and($user->fresh()->two_factor_confirmed_at->equalTo($confirmedAt))->toBeTrue();
});

it('regenerates recovery codes and dispatches an event', function (): void {
    Event::fake();
    $user = TwoFactorUser::factory()->create();
    $setup = app(StartEnrolment::class)->execute($user);

    $codes = app(RegenerateRecoveryCodes::class)->execute($user);

    expect($codes)->toHaveCount(8)
        ->and($codes)->not->toBe($setup->recoveryCodes)
        ->and($user->fresh()->twoFactorRecoveryCodes())->toBe($codes);
    Event::assertDispatched(RecoveryCodesRegenerated::class);
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
