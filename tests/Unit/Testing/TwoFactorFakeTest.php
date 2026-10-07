<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\Enums\TwoFactorMethod;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorAssertionFailedException;
use RoundlyConsulting\TwoFactor\Support\RecoveryCodeManager;
use RoundlyConsulting\TwoFactor\Testing\TwoFactorFake;
use RoundlyConsulting\TwoFactor\Tests\Fixtures\TwoFactorUser;

it('accepts every code by default', function (): void {
    $fake = app(TwoFactorFake::class);

    expect($fake->verify('secret', '000000'))->toBe(0)
        ->and($fake->currentCode('secret'))->toBe('123456');
});

it('rejects every code once told to reject', function (): void {
    $fake = app(TwoFactorFake::class)->reject();

    expect($fake->verify('secret', '123456'))->toBeFalse();
});

it('accepts only the configured code', function (): void {
    $fake = app(TwoFactorFake::class)->acceptCode('999111');

    expect($fake->verify('secret', '999111'))->toBe(0)
        ->and($fake->verify('secret', '000000'))->toBeFalse();
});

it('re-accepting clears a prior acceptCode restriction', function (): void {
    $fake = app(TwoFactorFake::class)->acceptCode('999111')->accept();

    expect($fake->verify('secret', '000000'))->toBe(0);
});

it('rejecting clears a prior acceptCode restriction', function (): void {
    $fake = app(TwoFactorFake::class)->acceptCode('999111')->reject();

    expect($fake->verify('secret', '999111'))->toBeFalse();
});

it('returns a canned secret respecting the requested length', function (): void {
    $fake = app(TwoFactorFake::class);

    expect($fake->generateSecret())->toHaveLength(16)
        ->and($fake->generateSecret(24))->toHaveLength(24)
        ->and($fake->generateSecret(0))->toBe('');
});

it('returns a programmed secret when set', function (): void {
    $fake = app(TwoFactorFake::class)->withSecret('MYSECRET');

    expect($fake->generateSecret())->toBe('MYSECRET');
});

it('returns canned recovery codes by count', function (): void {
    $fake = app(TwoFactorFake::class);

    expect($fake->generateRecoveryCodes())->toHaveCount(8)
        ->and($fake->generateRecoveryCodes(3))->toHaveCount(3);
});

it('hands back no recovery codes when none are asked for', function (int $count): void {
    $fake = app(TwoFactorFake::class);

    // The fake must agree with the real service, which returns an empty list.
    expect($fake->generateRecoveryCodes($count))
        ->toBe(app(RecoveryCodeManager::class)->generate($count));
})->with([
    'zero' => [0],
    'negative' => [-3],
]);

it('returns programmed recovery codes when set', function (): void {
    $fake = app(TwoFactorFake::class)->withRecoveryCodes('a', 'b');

    expect($fake->generateRecoveryCodes())->toBe(['a', 'b']);
});

it('builds a plausible provisioning uri without crypto', function (): void {
    $fake = app(TwoFactorFake::class);

    expect($fake->provisioningUri('SECRET', 'user@example.com', 'Acme'))
        ->toContain('otpauth://totp/')
        ->toContain('secret=SECRET')
        ->toContain('issuer=Acme');
});

it('records attempts and passes the outcome through', function (): void {
    $user = TwoFactorUser::factory()->withTwoFactor()->create();
    $fake = app(TwoFactorFake::class)->accept();

    expect($fake->for($user)->attempt('123456')->verified)->toBeTrue();

    $fake->assertVerified();
    $fake->assertVerifiedFor($user);
    $fake->assertVerifyCount(1);
    $fake->assertCodeAttempted('123456');
});

it('asserts a failed verification', function (): void {
    $user = TwoFactorUser::factory()->create();
    $fake = app(TwoFactorFake::class)->reject();

    $fake->for($user)->attempt('000000');

    $fake->assertVerificationFailed();
})->throwsNoExceptions();

it('asserts nothing verified when no calls were made', function (): void {
    app(TwoFactorFake::class)->assertNothingVerified();
})->throwsNoExceptions();

it('throws when assertVerified finds no success', function (): void {
    app(TwoFactorFake::class)->assertVerified();
})->throws(TwoFactorAssertionFailedException::class);

it('throws when assertVerifiedFor finds no matching success', function (): void {
    $user = TwoFactorUser::factory()->create();

    app(TwoFactorFake::class)->assertVerifiedFor($user);
})->throws(TwoFactorAssertionFailedException::class);

it('throws when assertVerificationFailed finds only successes', function (): void {
    $user = TwoFactorUser::factory()->withTwoFactor()->create();
    $fake = app(TwoFactorFake::class)->accept();
    $fake->for($user)->attempt('123456');

    $fake->assertVerificationFailed();
})->throws(TwoFactorAssertionFailedException::class);

it('throws when assertNothingVerified but calls were made', function (): void {
    $user = TwoFactorUser::factory()->create();
    $fake = app(TwoFactorFake::class)->accept();
    $fake->for($user)->attempt('123456');

    $fake->assertNothingVerified();
})->throws(TwoFactorAssertionFailedException::class);

it('throws when assertVerifyCount mismatches', function (): void {
    app(TwoFactorFake::class)->assertVerifyCount(2);
})->throws(TwoFactorAssertionFailedException::class);

it('throws when assertCodeAttempted finds no such code', function (): void {
    app(TwoFactorFake::class)->assertCodeAttempted('123456');
})->throws(TwoFactorAssertionFailedException::class);

it('attempts via totp by default, reporting the user stored count', function (): void {
    $user = TwoFactorUser::factory()->withTwoFactor()->create();
    $fake = app(TwoFactorFake::class);

    expect($fake->for($user->fresh())->attempt('123456'))
        ->verified->toBeTrue()
        ->method->toBe(TwoFactorMethod::Totp)
        ->remainingRecoveryCodes->toBe(8)
        ->replayed->toBeFalse();

    $fake->assertVerifiedVia(TwoFactorMethod::Totp);
    $fake->assertVerifyCount(1);
});

it('attempts via a recovery code, reporting one fewer than stored', function (): void {
    $user = TwoFactorUser::factory()->withTwoFactor()->create();
    $fake = app(TwoFactorFake::class)->acceptRecoveryCode();

    expect($fake->for($user->fresh())->attempt('ABCDE-FGHIJ'))
        ->verified->toBeTrue()
        ->method->toBe(TwoFactorMethod::RecoveryCode)
        ->remainingRecoveryCodes->toBe(7);

    $fake->assertVerifiedVia(TwoFactorMethod::RecoveryCode);
});

it('never reports a negative remaining count', function (): void {
    $fake = app(TwoFactorFake::class)->acceptRecoveryCode();

    expect($fake->for(TwoFactorUser::factory()->create())->attempt('ABCDE-FGHIJ')->remainingRecoveryCodes)->toBe(0)
        ->and(app(TwoFactorFake::class)->withRemainingRecoveryCodes(-4)->for(TwoFactorUser::factory()->create())->attempt('x')->remainingRecoveryCodes)->toBe(0);
});

it('reports a pinned remaining count for every outcome', function (): void {
    $user = TwoFactorUser::factory()->create();
    $fake = app(TwoFactorFake::class)->withRemainingRecoveryCodes(2);

    expect($fake->for($user)->attempt('123456')->remainingRecoveryCodes)->toBe(2)
        ->and($fake->acceptRecoveryCode()->for($user)->attempt('x')->remainingRecoveryCodes)->toBe(2)
        ->and($fake->reject()->for($user)->attempt('x')->remainingRecoveryCodes)->toBe(2)
        ->and($fake->replay()->for($user)->attempt('x')->remainingRecoveryCodes)->toBe(2);
});

it('fails an attempt with no method once told to reject', function (): void {
    $fake = app(TwoFactorFake::class)->reject();

    expect($fake->for(TwoFactorUser::factory()->create())->attempt('123456'))
        ->verified->toBeFalse()
        ->method->toBeNull()
        ->replayed->toBeFalse();

    $fake->assertVerificationFailed();
});

it('fails an attempt as replayed once told to replay', function (): void {
    $user = TwoFactorUser::factory()->withTwoFactor()->create();
    $fake = app(TwoFactorFake::class)->replay();

    expect($fake->for($user)->attempt('123456'))
        ->verified->toBeFalse()
        ->method->toBeNull()
        ->replayed->toBeTrue()
        ->and($fake->for($user)->attempt('123456')->verified)->toBeFalse()
        ->and($fake->verify('secret', '123456'))->toBeFalse();
});

it('clears replay mode when told to accept or accept a code', function (): void {
    $user = TwoFactorUser::factory()->withTwoFactor()->create();

    expect(app(TwoFactorFake::class)->replay()->accept()->for($user)->attempt('x')->verified)->toBeTrue()
        ->and(app(TwoFactorFake::class)->replay()->acceptRecoveryCode()->for($user)->attempt('x')->method)->toBe(TwoFactorMethod::RecoveryCode)
        ->and(app(TwoFactorFake::class)->replay()->acceptCode('111111')->for($user)->attempt('111111')->verified)->toBeTrue();
});

it('reports the current method for an accepted exact code', function (): void {
    $user = TwoFactorUser::factory()->withTwoFactor()->create();
    $fake = app(TwoFactorFake::class)->acceptRecoveryCode()->acceptCode('ABCDE-FGHIJ');

    expect($fake->for($user)->attempt('ABCDE-FGHIJ')->method)->toBe(TwoFactorMethod::RecoveryCode)
        ->and($fake->for($user)->attempt('KLMNP-QRSTU')->verified)->toBeFalse();
});

it('records every attempt', function (): void {
    $user = TwoFactorUser::factory()->withTwoFactor()->create();
    $fake = app(TwoFactorFake::class);

    $fake->for($user)->attempt('111111');
    $fake->for($user)->attempt('222222');

    $fake->assertVerifyCount(2);
    $fake->assertCodeAttempted('111111');
    $fake->assertCodeAttempted('222222');
    $fake->assertVerifiedFor($user);
})->throwsNoExceptions();

it('throws when assertVerifiedVia finds no success by that method', function (): void {
    $user = TwoFactorUser::factory()->create();
    $fake = app(TwoFactorFake::class);
    $fake->for($user)->attempt('123456');

    $fake->assertVerifiedVia(TwoFactorMethod::RecoveryCode);
})->throws(TwoFactorAssertionFailedException::class, 'recovery_code');

it('throws when assertVerifiedVia only saw failures', function (): void {
    $user = TwoFactorUser::factory()->create();
    $fake = app(TwoFactorFake::class)->reject();
    $fake->for($user)->attempt('123456');

    $fake->assertVerifiedVia(TwoFactorMethod::Totp);
})->throws(TwoFactorAssertionFailedException::class);

/**
 * The fake must never pass a challenge the real action refuses: only a confirmed enrolment
 * is a working second factor, so a host test cannot go green on a user who never enrolled.
 */
it('fails an attempt for a user without confirmed two-factor, like the real action', function (Closure $prepare): void {
    $user = TwoFactorUser::factory()->create();
    $prepare($user);
    $fake = app(TwoFactorFake::class)->accept();

    expect($fake->for($user->fresh())->attempt('123456'))
        ->verified->toBeFalse()
        ->method->toBeNull()
        ->replayed->toBeFalse()
        ->and($fake->acceptRecoveryCode()->for($user->fresh())->attempt('ABCDE-FGHIJ')->verified)->toBeFalse()
        ->and($fake->replay()->for($user->fresh())->attempt('123456')->replayed)->toBeFalse();

    $fake->assertVerifyCount(3);
    $fake->assertVerificationFailed();
    expect(fn () => $fake->assertVerified())->toThrow(TwoFactorAssertionFailedException::class);
})->with([
    'never enrolled' => [fn (TwoFactorUser $user): null => null],
    'pending enrolment' => [fn (TwoFactorUser $user): mixed => $user->startTwoFactorEnrolment()],
]);
