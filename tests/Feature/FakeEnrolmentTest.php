<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\Contracts\TwoFactorService;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorCodeException;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorAssertionFailedException;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;
use RoundlyConsulting\TwoFactor\Testing\RecordingUserRecoveryCodes;
use RoundlyConsulting\TwoFactor\Testing\RecordingUserTwoFactor;
use RoundlyConsulting\TwoFactor\Testing\TwoFactorFake;
use RoundlyConsulting\TwoFactor\Tests\Fixtures\TwoFactorUser;

it('hands out recording handles', function (): void {
    $fake = TwoFactor::fake();
    $handle = TwoFactor::for(TwoFactorUser::factory()->create());

    expect($handle)->toBeInstanceOf(RecordingUserTwoFactor::class)
        ->and($handle->recoveryCodes())->toBeInstanceOf(RecordingUserRecoveryCodes::class)
        ->and(app(TwoFactorService::class))->toBe($fake);
});

it('records enrolment writes made through the facade', function (): void {
    $fake = TwoFactor::fake()->withSecret('FAKESECRET234567');
    $user = TwoFactorUser::factory()->create();

    $setup = TwoFactor::for($user)->start();
    TwoFactor::for($user->fresh())->confirm('123456');
    $codes = TwoFactor::for($user->fresh())->recoveryCodes()->regenerate();
    TwoFactor::for($user->fresh())->disable();

    expect($setup->secret)->toBe('FAKESECRET234567')
        ->and($codes)->toHaveCount(8)
        ->and($user->fresh()->hasTwoFactorEnabled())->toBeFalse();

    $fake->assertStarted($user);
    $fake->assertConfirmed($user);
    $fake->assertRegenerated($user);
    $fake->assertDisabled($user);
    $fake->assertCodeAttempted('123456');
});

it('records enrolment writes made through the model verbs', function (): void {
    $fake = TwoFactor::fake();
    $user = TwoFactorUser::factory()->create();

    $user->startTwoFactorEnrolment();
    $user->fresh()->confirmTwoFactor('123456');
    $user->fresh()->regenerateTwoFactorRecoveryCodes();
    $user->fresh()->disableTwoFactor();

    $fake->assertStarted();
    $fake->assertConfirmed();
    $fake->assertRegenerated();
    $fake->assertDisabled();
})->throwsNoExceptions();

it('records attempts made through the model verbs', function (): void {
    $fake = TwoFactor::fake()->reject();
    $user = TwoFactorUser::factory()->create();

    expect($user->attemptTwoFactorCode('000000')->verified)->toBeFalse();

    $fake->assertVerificationFailed();
    $fake->assertVerifyCount(1);
});

it('reads status and remaining codes through to the model under the fake', function (): void {
    TwoFactor::fake();
    $user = TwoFactorUser::factory()->create();
    TwoFactor::for($user)->start();

    expect(TwoFactor::for($user)->status()->pending)->toBeTrue()
        ->and(TwoFactor::for($user)->recoveryCodes()->remaining())->toBe(8);
});

it('passes every assertNothing when nothing ran', function (): void {
    $fake = TwoFactor::fake();

    $fake->assertNothingStarted();
    $fake->assertNothingConfirmed();
    $fake->assertNothingDisabled();
    $fake->assertNothingRegenerated();
    $fake->assertNothingVerified();
})->throwsNoExceptions();

it('does not record a confirmation that failed', function (): void {
    $fake = TwoFactor::fake();
    $user = TwoFactorUser::factory()->create();
    $user->startTwoFactorEnrolment();
    $fake->reject();

    expect(fn () => $user->fresh()->confirmTwoFactor('000000'))->toThrow(InvalidTwoFactorCodeException::class);

    $fake->assertNothingConfirmed();
});

it('fails an assert when nothing was recorded', function (string $assert): void {
    app(TwoFactorFake::class)->{$assert}();
})->with([
    'assertStarted',
    'assertConfirmed',
    'assertDisabled',
    'assertRegenerated',
])->throws(TwoFactorAssertionFailedException::class, 'none was recorded');

it('fails an assert recorded only for another user', function (string $verb, string $assert): void {
    $fake = TwoFactor::fake();
    $user = TwoFactorUser::factory()->create();
    $other = TwoFactorUser::factory()->create();

    $user->startTwoFactorEnrolment();

    match ($verb) {
        'confirm' => $user->fresh()->confirmTwoFactor('123456'),
        'regenerate' => $user->fresh()->regenerateTwoFactorRecoveryCodes(),
        'disable' => $user->fresh()->disableTwoFactor(),
        default => null,
    };

    $fake->{$assert}($user);
    $fake->{$assert}($other);
})->with([
    'start' => ['start', 'assertStarted'],
    'confirm' => ['confirm', 'assertConfirmed'],
    'regenerate' => ['regenerate', 'assertRegenerated'],
    'disable' => ['disable', 'assertDisabled'],
])->throws(TwoFactorAssertionFailedException::class, 'for the given user');

it('fails an assertNothing once the write was recorded', function (string $verb, string $assert): void {
    $fake = TwoFactor::fake();
    $user = TwoFactorUser::factory()->create();

    $user->startTwoFactorEnrolment();

    match ($verb) {
        'confirm' => $user->fresh()->confirmTwoFactor('123456'),
        'regenerate' => $user->fresh()->regenerateTwoFactorRecoveryCodes(),
        'disable' => $user->fresh()->disableTwoFactor(),
        default => null,
    };

    $fake->{$assert}();
})->with([
    'start' => ['start', 'assertNothingStarted'],
    'confirm' => ['confirm', 'assertNothingConfirmed'],
    'regenerate' => ['regenerate', 'assertNothingRegenerated'],
    'disable' => ['disable', 'assertNothingDisabled'],
])->throws(TwoFactorAssertionFailedException::class, 'were recorded');
