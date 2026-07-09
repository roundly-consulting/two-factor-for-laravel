<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\Actions\ConfirmEnrolment;
use RoundlyConsulting\TwoFactor\Actions\StartEnrolment;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorService;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;
use RoundlyConsulting\TwoFactor\Testing\FakeTwoFactor;
use RoundlyConsulting\TwoFactor\Tests\Fixtures\TwoFactorUser;

it('swaps the bound service for the fake', function (): void {
    $fake = TwoFactor::fake();

    expect($fake)->toBeInstanceOf(FakeTwoFactor::class)
        ->and(app(TwoFactorService::class))->toBe($fake);
});

it('drives verifyFor through the facade without real totp', function (): void {
    $fake = TwoFactor::fake()->accept();
    $user = TwoFactorUser::factory()->create();

    expect(TwoFactor::verifyFor($user, '123456'))->toBeTrue();

    $fake->assertVerifiedFor($user);
});

it('rejects through the facade when told to reject', function (): void {
    TwoFactor::fake()->reject();
    $user = TwoFactorUser::factory()->create();

    expect(TwoFactor::verifyFor($user, '000000'))->toBeFalse();
});

it('lets an action-based enrolment run against the fake with no crypto', function (): void {
    $fake = TwoFactor::fake()->withSecret('FAKESECRET234567');
    $user = TwoFactorUser::factory()->create();

    $setup = app(StartEnrolment::class)->execute($user);
    app(ConfirmEnrolment::class)->execute($user->fresh(), '123456');

    expect($user->fresh()->hasTwoFactorEnabled())->toBeTrue()
        ->and($setup->secret)->toBe('FAKESECRET234567');
    $fake->assertCodeAttempted('123456');
});
