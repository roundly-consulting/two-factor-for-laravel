<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use RoundlyConsulting\TwoFactor\DataTransferObjects\TwoFactorSetup;
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

it('matches the facade verifyFor result', function (): void {
    $fake = TwoFactor::fake()->accept();
    $user = TwoFactorUser::factory()->create();

    expect($user->verifyTwoFactorCode('123456'))->toBeTrue();
    $fake->assertVerifiedFor($user);
});

it('regenerates recovery codes through the trait verb', function (): void {
    $user = TwoFactorUser::factory()->create();
    $setup = $user->startTwoFactorEnrolment();

    $codes = $user->regenerateTwoFactorRecoveryCodes();

    expect($codes)->toHaveCount(8)
        ->and($codes)->not->toBe($setup->recoveryCodes)
        ->and($user->fresh()->twoFactorRecoveryCodes())->toBe($codes);
});

it('tracks the remaining recovery-code count', function (): void {
    $user = TwoFactorUser::factory()->create();
    $setup = $user->startTwoFactorEnrolment();

    expect($user->fresh()->twoFactorRecoveryCodesRemaining())->toBe(8);

    TwoFactor::verifyFor($user->fresh(), $setup->recoveryCodes[0]);

    expect($user->fresh()->twoFactorRecoveryCodesRemaining())->toBe(7);
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
