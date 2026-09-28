<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use RoundlyConsulting\TwoFactor\DataTransferObjects\TwoFactorSetup;
use RoundlyConsulting\TwoFactor\DataTransferObjects\VerificationResult;
use RoundlyConsulting\TwoFactor\Enums\TwoFactorMethod;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;
use RoundlyConsulting\TwoFactor\Tests\Fixtures\CustomLabelUser;
use RoundlyConsulting\TwoFactor\Tests\Fixtures\TwoFactorUser;

it('starts enrolment through the trait verb', function (): void {
    $user = TwoFactorUser::factory()->create();

    $setup = $user->startTwoFactorEnrolment();

    expect($setup)->toBeInstanceOf(TwoFactorSetup::class)
        ->and($user->fresh()->hasPendingTwoFactor())->toBeTrue();
});

it('confirms, verifies and disables through the trait verbs', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    $user = TwoFactorUser::factory()->create();
    $setup = $user->startTwoFactorEnrolment();

    $user->confirmTwoFactor(TwoFactor::currentCode($setup->secret));
    expect($user->fresh()->hasTwoFactorEnabled())->toBeTrue();

    // Advance a step so the confirming timestep is not replayed.
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_060));
    $fresh = $user->fresh();
    expect($fresh->verifyTwoFactorCode(TwoFactor::currentCode($setup->secret)))->toBeTrue();

    $fresh->disableTwoFactor();
    expect($user->fresh()->hasTwoFactorEnabled())->toBeFalse();

    Carbon::setTestNow();
});

it('reduces the facade attempt to a bool', function (): void {
    $fake = TwoFactor::fake()->accept();
    $user = TwoFactorUser::factory()->create();

    expect($user->verifyTwoFactorCode('123456'))->toBeTrue();
    $fake->assertVerifiedFor($user);
});

it('attempts a code through the trait verb and reports the method', function (): void {
    $fake = TwoFactor::fake()->acceptRecoveryCode()->withRemainingRecoveryCodes(3);
    $user = TwoFactorUser::factory()->create();

    $result = $user->attemptTwoFactorCode('ABCDE-FGHIJ');

    expect($result)->toBeInstanceOf(VerificationResult::class)
        ->verified->toBeTrue()
        ->method->toBe(TwoFactorMethod::RecoveryCode)
        ->remainingRecoveryCodes->toBe(3);
    $fake->assertVerifiedVia(TwoFactorMethod::RecoveryCode);
});

it('brands the enrolment with a per-call issuer through the trait verb', function (): void {
    config(['two-factor.issuer' => 'Configured']);
    $user = TwoFactorUser::factory()->create(['email' => 'jane@acme.io']);

    $setup = $user->startTwoFactorEnrolment(issuer: 'Clients Portal');

    expect($setup->issuer)->toBe('Clients Portal')
        ->and($setup->provisioningUri)->toStartWith('otpauth://totp/Clients%20Portal:jane%40acme.io?')
        ->and($setup->provisioningUri)->toContain('issuer=Clients%20Portal');
});

it('regenerates recovery codes through the trait verb', function (): void {
    $user = TwoFactorUser::factory()->create();
    $setup = $user->startTwoFactorEnrolment();

    $codes = $user->regenerateTwoFactorRecoveryCodes();

    // Hashed at rest by default: the stored list is not the returned plaintext.
    expect($codes)->toHaveCount(8)
        ->and($codes)->not->toBe($setup->recoveryCodes)
        ->and($user->fresh()->twoFactorRecoveryCodesRemaining())->toBe(8)
        ->and($user->fresh()->twoFactorRecoveryCodes())->not->toBe($codes);
});

it('tracks the remaining recovery-code count', function (): void {
    $user = TwoFactorUser::factory()->create();
    $setup = $user->startTwoFactorEnrolment();
    $user->setAttribute((string) config('two-factor.columns.confirmed_at'), now())->save();

    expect($user->fresh()->twoFactorRecoveryCodesRemaining())->toBe(8);

    TwoFactor::for($user->fresh())->attempt($setup->recoveryCodes[0]);

    expect($user->fresh()->twoFactorRecoveryCodesRemaining())->toBe(7);
});

it('hides the sensitive two-factor columns from serialization', function (): void {
    $user = TwoFactorUser::factory()->create();
    $user->startTwoFactorEnrolment();
    $user->setAttribute((string) config('two-factor.columns.confirmed_at'), now())->save();

    $fresh = $user->fresh();
    $array = $fresh->toArray();
    $json = $fresh->toJson();

    foreach (['two_factor_secret', 'two_factor_recovery_codes', 'two_factor_last_used_timestep'] as $column) {
        expect($array)->not->toHaveKey($column)
            ->and($json)->not->toContain($column);
    }

    // The confirmed_at marker stays visible so hosts can render enrolment state.
    expect($array)->toHaveKey('two_factor_confirmed_at');
});

it('defaults the provisioning label to the email', function (): void {
    $user = TwoFactorUser::factory()->create(['email' => 'jane@example.com']);

    expect($user->twoFactorLabel())->toBe('jane@example.com');
});

it('reflects an overridden twoFactorLabel in the provisioning uri', function (): void {
    $user = new CustomLabelUser;
    $user->forceFill(['email' => 'ignored@example.com'])->save();

    $setup = $user->startTwoFactorEnrolment();

    expect($setup->provisioningUri)->toContain(rawurlencode('custom-label'));
});
