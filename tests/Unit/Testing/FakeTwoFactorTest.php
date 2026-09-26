<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\Enums\TwoFactorMethod;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorAssertionFailedException;
use RoundlyConsulting\TwoFactor\Support\RecoveryCodeManager;
use RoundlyConsulting\TwoFactor\Testing\FakeTwoFactor;
use RoundlyConsulting\TwoFactor\Tests\Fixtures\TwoFactorUser;

it('accepts every code by default', function (): void {
    $fake = new FakeTwoFactor;

    expect($fake->verify('secret', '000000'))->toBe(0)
        ->and($fake->currentCode('secret'))->toBe('123456');
});

it('rejects every code once told to reject', function (): void {
    $fake = (new FakeTwoFactor)->reject();

    expect($fake->verify('secret', '123456'))->toBeFalse();
});

it('accepts only the configured code', function (): void {
    $fake = (new FakeTwoFactor)->acceptCode('999111');

    expect($fake->verify('secret', '999111'))->toBe(0)
        ->and($fake->verify('secret', '000000'))->toBeFalse();
});

it('re-accepting clears a prior acceptCode restriction', function (): void {
    $fake = (new FakeTwoFactor)->acceptCode('999111')->accept();

    expect($fake->verify('secret', '000000'))->toBe(0);
});

it('rejecting clears a prior acceptCode restriction', function (): void {
    $fake = (new FakeTwoFactor)->acceptCode('999111')->reject();

    expect($fake->verify('secret', '999111'))->toBeFalse();
});

it('returns a canned secret respecting the requested length', function (): void {
    $fake = new FakeTwoFactor;

    expect($fake->generateSecret())->toHaveLength(16)
        ->and($fake->generateSecret(24))->toHaveLength(24)
        ->and($fake->generateSecret(0))->toBe('');
});

it('returns a programmed secret when set', function (): void {
    $fake = (new FakeTwoFactor)->withSecret('MYSECRET');

    expect($fake->generateSecret())->toBe('MYSECRET');
});

it('returns canned recovery codes by count', function (): void {
    $fake = new FakeTwoFactor;

    expect($fake->generateRecoveryCodes())->toHaveCount(8)
        ->and($fake->generateRecoveryCodes(3))->toHaveCount(3);
});

it('hands back no recovery codes when none are asked for', function (int $count): void {
    $fake = new FakeTwoFactor;

    // The fake must agree with the real service, which returns an empty list.
    expect($fake->generateRecoveryCodes($count))
        ->toBe(app(RecoveryCodeManager::class)->generate($count));
})->with([
    'zero' => [0],
    'negative' => [-3],
]);

it('returns programmed recovery codes when set', function (): void {
    $fake = (new FakeTwoFactor)->withRecoveryCodes('a', 'b');

    expect($fake->generateRecoveryCodes())->toBe(['a', 'b']);
});

it('builds a plausible provisioning uri without crypto', function (): void {
    $fake = new FakeTwoFactor;

    expect($fake->provisioningUri('SECRET', 'user@example.com', 'Acme'))
        ->toContain('otpauth://totp/')
        ->toContain('secret=SECRET')
        ->toContain('issuer=Acme');
});

it('records verifyFor calls and passes the outcome through', function (): void {
    $user = TwoFactorUser::factory()->create();
    $fake = (new FakeTwoFactor)->accept();

    expect($fake->verifyFor($user, '123456'))->toBeTrue();

    $fake->assertVerified();
    $fake->assertVerifiedFor($user);
    $fake->assertVerifyCount(1);
    $fake->assertCodeAttempted('123456');
});

it('asserts a failed verification', function (): void {
    $user = TwoFactorUser::factory()->create();
    $fake = (new FakeTwoFactor)->reject();

    $fake->verifyFor($user, '000000');

    $fake->assertVerificationFailed();
})->throwsNoExceptions();

it('asserts nothing verified when no calls were made', function (): void {
    (new FakeTwoFactor)->assertNothingVerified();
})->throwsNoExceptions();

it('throws when assertVerified finds no success', function (): void {
    (new FakeTwoFactor)->assertVerified();
})->throws(TwoFactorAssertionFailedException::class);

it('throws when assertVerifiedFor finds no matching success', function (): void {
    $user = TwoFactorUser::factory()->create();

    (new FakeTwoFactor)->assertVerifiedFor($user);
})->throws(TwoFactorAssertionFailedException::class);

it('throws when assertVerificationFailed finds only successes', function (): void {
    $user = TwoFactorUser::factory()->create();
    $fake = (new FakeTwoFactor)->accept();
    $fake->verifyFor($user, '123456');

    $fake->assertVerificationFailed();
})->throws(TwoFactorAssertionFailedException::class);

it('throws when assertNothingVerified but calls were made', function (): void {
    $user = TwoFactorUser::factory()->create();
    $fake = (new FakeTwoFactor)->accept();
    $fake->verifyFor($user, '123456');

    $fake->assertNothingVerified();
})->throws(TwoFactorAssertionFailedException::class);

it('throws when assertVerifyCount mismatches', function (): void {
    (new FakeTwoFactor)->assertVerifyCount(2);
})->throws(TwoFactorAssertionFailedException::class);

it('throws when assertCodeAttempted finds no such code', function (): void {
    (new FakeTwoFactor)->assertCodeAttempted('123456');
})->throws(TwoFactorAssertionFailedException::class);

it('attempts via totp by default, reporting the user stored count', function (): void {
    $user = TwoFactorUser::factory()->create();
    $user->startTwoFactorEnrolment();
    $fake = new FakeTwoFactor;

    expect($fake->attempt($user->fresh(), '123456'))
        ->verified->toBeTrue()
        ->method->toBe(TwoFactorMethod::Totp)
        ->remainingRecoveryCodes->toBe(8)
        ->replayed->toBeFalse();

    $fake->assertVerifiedVia(TwoFactorMethod::Totp);
    $fake->assertVerifyCount(1);
});

it('attempts via a recovery code, reporting one fewer than stored', function (): void {
    $user = TwoFactorUser::factory()->create();
    $user->startTwoFactorEnrolment();
    $fake = (new FakeTwoFactor)->acceptRecoveryCode();

    expect($fake->attempt($user->fresh(), 'ABCDE-FGHIJ'))
        ->verified->toBeTrue()
        ->method->toBe(TwoFactorMethod::RecoveryCode)
        ->remainingRecoveryCodes->toBe(7);

    $fake->assertVerifiedVia(TwoFactorMethod::RecoveryCode);
});

it('never reports a negative remaining count', function (): void {
    $fake = (new FakeTwoFactor)->acceptRecoveryCode();

    expect($fake->attempt(TwoFactorUser::factory()->create(), 'ABCDE-FGHIJ')->remainingRecoveryCodes)->toBe(0)
        ->and((new FakeTwoFactor)->withRemainingRecoveryCodes(-4)->attempt(TwoFactorUser::factory()->create(), 'x')->remainingRecoveryCodes)->toBe(0);
});

it('reports a pinned remaining count for every outcome', function (): void {
    $user = TwoFactorUser::factory()->create();
    $fake = (new FakeTwoFactor)->withRemainingRecoveryCodes(2);

    expect($fake->attempt($user, '123456')->remainingRecoveryCodes)->toBe(2)
        ->and($fake->acceptRecoveryCode()->attempt($user, 'x')->remainingRecoveryCodes)->toBe(2)
        ->and($fake->reject()->attempt($user, 'x')->remainingRecoveryCodes)->toBe(2)
        ->and($fake->replay()->attempt($user, 'x')->remainingRecoveryCodes)->toBe(2);
});

it('fails an attempt with no method once told to reject', function (): void {
    $fake = (new FakeTwoFactor)->reject();

    expect($fake->attempt(TwoFactorUser::factory()->create(), '123456'))
        ->verified->toBeFalse()
        ->method->toBeNull()
        ->replayed->toBeFalse();

    $fake->assertVerificationFailed();
});

it('fails an attempt as replayed once told to replay', function (): void {
    $user = TwoFactorUser::factory()->create();
    $fake = (new FakeTwoFactor)->replay();

    expect($fake->attempt($user, '123456'))
        ->verified->toBeFalse()
        ->method->toBeNull()
        ->replayed->toBeTrue()
        ->and($fake->verifyFor($user, '123456'))->toBeFalse()
        ->and($fake->verify('secret', '123456'))->toBeFalse();
});

it('clears replay mode when told to accept or accept a code', function (): void {
    $user = TwoFactorUser::factory()->create();

    expect((new FakeTwoFactor)->replay()->accept()->attempt($user, 'x')->verified)->toBeTrue()
        ->and((new FakeTwoFactor)->replay()->acceptRecoveryCode()->attempt($user, 'x')->method)->toBe(TwoFactorMethod::RecoveryCode)
        ->and((new FakeTwoFactor)->replay()->acceptCode('111111')->attempt($user, '111111')->verified)->toBeTrue();
});

it('reports the current method for an accepted exact code', function (): void {
    $user = TwoFactorUser::factory()->create();
    $fake = (new FakeTwoFactor)->acceptRecoveryCode()->acceptCode('ABCDE-FGHIJ');

    expect($fake->attempt($user, 'ABCDE-FGHIJ')->method)->toBe(TwoFactorMethod::RecoveryCode)
        ->and($fake->attempt($user, 'KLMNP-QRSTU')->verified)->toBeFalse();
});

it('records verifyFor and attempt alike', function (): void {
    $user = TwoFactorUser::factory()->create();
    $fake = new FakeTwoFactor;

    $fake->attempt($user, '111111');
    $fake->verifyFor($user, '222222');

    $fake->assertVerifyCount(2);
    $fake->assertCodeAttempted('111111');
    $fake->assertCodeAttempted('222222');
    $fake->assertVerifiedFor($user);
})->throwsNoExceptions();

it('throws when assertVerifiedVia finds no success by that method', function (): void {
    $user = TwoFactorUser::factory()->create();
    $fake = new FakeTwoFactor;
    $fake->attempt($user, '123456');

    $fake->assertVerifiedVia(TwoFactorMethod::RecoveryCode);
})->throws(TwoFactorAssertionFailedException::class, 'recovery_code');

it('throws when assertVerifiedVia only saw failures', function (): void {
    $user = TwoFactorUser::factory()->create();
    $fake = (new FakeTwoFactor)->reject();
    $fake->attempt($user, '123456');

    $fake->assertVerifiedVia(TwoFactorMethod::Totp);
})->throws(TwoFactorAssertionFailedException::class);
