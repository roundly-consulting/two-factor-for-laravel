<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use RoundlyConsulting\Crypto\Codec\Base32;
use RoundlyConsulting\Crypto\Otp\OtpAlgorithm;
use RoundlyConsulting\Crypto\Otp\Totp;
use RoundlyConsulting\TwoFactor\Actions\StartEnrolment;
use RoundlyConsulting\TwoFactor\DataTransferObjects\TwoFactorSetup;
use RoundlyConsulting\TwoFactor\DataTransferObjects\VerificationResult;
use RoundlyConsulting\TwoFactor\Enums\TwoFactorMethod;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidBase32Exception;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorConfigException;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorRateLimitedException;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;
use RoundlyConsulting\TwoFactor\Tests\Fixtures\TwoFactorUser;

/** The RFC 4226 test seed, as the base32 an authenticator app would show. */
function testSecret(): string
{
    return Base32::encode('12345678901234567890');
}

it('generates a base32 secret of the configured length', function (): void {
    $secret = TwoFactor::generateSecret();

    expect($secret)->toHaveLength(32) // 32 base32 chars = 160 bits (RFC 4226 recommendation)
        ->and(Base32::decode($secret))->not->toBe(''); // decodes cleanly
});

it('generates a secret that round-trips through the strict codec', function (int $length): void {
    $secret = TwoFactor::generateSecret($length);

    expect($secret)->toHaveLength($length)
        ->and(Base32::decode($secret))->not->toBe('');
})->with([16, 20, 26, 32, 40]);

it('honours an explicit secret length', function (): void {
    expect(TwoFactor::generateSecret(32))->toHaveLength(32);
});

it('generates distinct secrets', function (): void {
    expect(TwoFactor::generateSecret())->not->toBe(TwoFactor::generateSecret());
});

it('refuses to mint a secret below the entropy floor', function (): void {
    TwoFactor::generateSecret(8);
})->throws(InvalidTwoFactorConfigException::class);

it('refuses an absurdly long secret length', function (): void {
    TwoFactor::generateSecret(100_000);
})->throws(InvalidTwoFactorConfigException::class);

it('rejects a configured secret length below the entropy floor', function (): void {
    config(['two-factor.secret_length' => 10]);

    TwoFactor::generateSecret();
})->throws(InvalidTwoFactorConfigException::class);

it('verifies its own current code', function (): void {
    $secret = TwoFactor::generateSecret();

    expect(TwoFactor::verify($secret, TwoFactor::currentCode($secret)))->not->toBeFalse();
});

it('generates the configured number of recovery codes', function (): void {
    expect(TwoFactor::generateRecoveryCodes())->toHaveCount(8)
        ->and(TwoFactor::generateRecoveryCodes(3))->toHaveCount(3);
});

it('produces the code for an explicit timestamp', function (): void {
    // RFC 6238 Appendix B, SHA-1, T=59 truncated to the default 6 digits.
    expect(TwoFactor::currentCode(testSecret(), 59))->toBe('287082');
});

it('rejects a malformed code before doing any hmac work', function (string $code): void {
    expect(TwoFactor::verify(testSecret(), $code))->toBeFalse();
})->with(['', '12345', '1234567', 'abcdef', '12 456']);

it('accepts drift of exactly one timestep either side by default', function (): void {
    $secret = testSecret();
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000)); // step 56666666

    $previous = TwoFactor::currentCode($secret, 1_700_000_000 - 30);
    $next = TwoFactor::currentCode($secret, 1_700_000_000 + 30);

    expect(TwoFactor::verify($secret, $previous))->toBe(56_666_665)
        ->and(TwoFactor::verify($secret, $next))->toBe(56_666_667);

    Carbon::setTestNow();
});

it('rejects drift beyond the configured window', function (): void {
    $secret = testSecret();
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));

    // Default window is 1 step, so ±2 steps must not be accepted.
    expect(TwoFactor::verify($secret, TwoFactor::currentCode($secret, 1_700_000_000 - 60)))->toBeFalse()
        ->and(TwoFactor::verify($secret, TwoFactor::currentCode($secret, 1_700_000_000 + 60)))->toBeFalse();

    Carbon::setTestNow();
});

it('accepts no drift at all with a zero window', function (): void {
    config(['two-factor.window' => 0]);
    $secret = testSecret();
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));

    expect(TwoFactor::verify($secret, TwoFactor::currentCode($secret)))->toBe(56_666_666)
        ->and(TwoFactor::verify($secret, TwoFactor::currentCode($secret, 1_700_000_000 - 30)))->toBeFalse();

    Carbon::setTestNow();
});

it('widens to two steps when the window is configured to two', function (): void {
    config(['two-factor.window' => 2]);
    $secret = testSecret();
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));

    expect(TwoFactor::verify($secret, TwoFactor::currentCode($secret, 1_700_000_000 - 60)))->toBe(56_666_664)
        ->and(TwoFactor::verify($secret, TwoFactor::currentCode($secret, 1_700_000_000 - 90)))->toBeFalse();

    Carbon::setTestNow();
});

it('rejects a configured window wider than two steps', function (): void {
    config(['two-factor.window' => 3]);

    TwoFactor::verify(testSecret(), '123456');
})->throws(InvalidTwoFactorConfigException::class);

it('rejects an explicit window the otp primitive will not honour', function (): void {
    TwoFactor::verify(testSecret(), '123456', 50);
})->throws(InvalidTwoFactorConfigException::class);

it('surfaces a malformed secret as an invalid base32 exception when verifying', function (): void {
    TwoFactor::verify('MZXW6YTB01', '123456'); // 0 and 1 are outside the alphabet
})->throws(InvalidBase32Exception::class);

it('surfaces a malformed secret as an invalid base32 exception when generating a code', function (): void {
    TwoFactor::currentCode('MZXW6YTB01');
})->throws(InvalidBase32Exception::class);

it('produces a different code per configured algorithm', function (): void {
    $secret = testSecret();

    $sha1 = TwoFactor::currentCode($secret, 1_111_111_111);

    config(['two-factor.algorithm' => OtpAlgorithm::Sha256->value]);
    $sha256 = TwoFactor::currentCode($secret, 1_111_111_111);

    config(['two-factor.algorithm' => OtpAlgorithm::Sha512->value]);
    $sha512 = TwoFactor::currentCode($secret, 1_111_111_111);

    expect($sha1)->not->toBe($sha256)
        ->and($sha256)->not->toBe($sha512);
});

it('keeps the meaning of every supported algorithm config value', function (string $configured, OtpAlgorithm $expected): void {
    config(['two-factor.algorithm' => $configured]);
    $secret = testSecret();

    // The configured string must still select exactly the hash it always did.
    expect(TwoFactor::currentCode($secret, 1_111_111_111))
        ->toBe((new Totp($expected, 6, 30))->codeAt($secret, 1_111_111_111));
})->with([
    ['sha1', OtpAlgorithm::Sha1],
    ['sha256', OtpAlgorithm::Sha256],
    ['sha512', OtpAlgorithm::Sha512],
]);

it('rejects an unsupported algorithm rather than downgrading the hash', function (): void {
    config(['two-factor.algorithm' => 'md5']);

    TwoFactor::currentCode(testSecret());
})->throws(InvalidTwoFactorConfigException::class);

/**
 * A confirmed enrolment with an untouched replay guard (confirmed_at stamped
 * directly, so no timestep is spent before the test runs).
 *
 * @return array{0: TwoFactorUser, 1: TwoFactorSetup}
 */
function attemptableUser(): array
{
    $user = TwoFactorUser::factory()->create();
    $setup = app(StartEnrolment::class)->execute($user);

    $user->setAttribute((string) config('two-factor.columns.confirmed_at'), now());
    $user->save();

    /** @var TwoFactorUser $fresh */
    $fresh = $user->fresh();

    return [$fresh, $setup];
}

it('attempts a totp code and reports it with the recovery codes untouched', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    [$user, $setup] = attemptableUser();

    $result = TwoFactor::attempt($user, TwoFactor::currentCode($setup->secret));

    expect($result)->toBeInstanceOf(VerificationResult::class)
        ->verified->toBeTrue()
        ->method->toBe(TwoFactorMethod::Totp)
        ->remainingRecoveryCodes->toBe(8)
        ->replayed->toBeFalse();

    Carbon::setTestNow();
});

it('attempts a recovery code and reports one fewer remaining', function (): void {
    [$user, $setup] = attemptableUser();

    expect(TwoFactor::attempt($user, $setup->recoveryCodes[0]))
        ->verified->toBeTrue()
        ->method->toBe(TwoFactorMethod::RecoveryCode)
        ->remainingRecoveryCodes->toBe(7)
        ->replayed->toBeFalse();

    expect(TwoFactor::attempt($user->fresh(), $setup->recoveryCodes[1]))
        ->remainingRecoveryCodes->toBe(6);
});

it('reports a replayed timestep as a failure flagged replayed', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    [$user, $setup] = attemptableUser();
    $code = TwoFactor::currentCode($setup->secret);

    expect(TwoFactor::attempt($user, $code)->verified)->toBeTrue();

    expect(TwoFactor::attempt($user->fresh(), $code))
        ->verified->toBeFalse()
        ->method->toBeNull()
        ->replayed->toBeTrue()
        ->remainingRecoveryCodes->toBe(8);

    Carbon::setTestNow();
});

it('reports a wrong code as a plain failure', function (): void {
    [$user] = attemptableUser();

    expect(TwoFactor::attempt($user, '000000'))
        ->verified->toBeFalse()
        ->method->toBeNull()
        ->replayed->toBeFalse()
        ->remainingRecoveryCodes->toBe(8);
});

it('fails a pending enrolment even with its valid code', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    $user = TwoFactorUser::factory()->create();
    $setup = app(StartEnrolment::class)->execute($user);

    expect(TwoFactor::attempt($user->fresh(), TwoFactor::currentCode($setup->secret)))
        ->verified->toBeFalse()
        ->method->toBeNull()
        ->remainingRecoveryCodes->toBe(8);

    Carbon::setTestNow();
});

it('fails a user with no enrolment at all', function (): void {
    expect(TwoFactor::attempt(TwoFactorUser::factory()->create(), '123456'))
        ->verified->toBeFalse()
        ->remainingRecoveryCodes->toBe(0);
});

it('throws once the per-user limiter is exhausted', function (): void {
    config(['two-factor.attempts' => ['max' => 2, 'decay' => 60]]);
    [$user] = attemptableUser();

    TwoFactor::attempt($user, '000000');
    TwoFactor::attempt($user, '000000');

    TwoFactor::attempt($user, '000000');
})->throws(TwoFactorRateLimitedException::class);

it('agrees with verifyFor for every outcome', function (string $kind, bool $expected): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));

    // Two identical users so each call sees the same state rather than the
    // other's side effects (a spent code, a claimed timestep).
    [$a, $setupA] = attemptableUser();
    [$b, $setupB] = attemptableUser();

    $code = static fn (TwoFactorSetup $setup): string => match ($kind) {
        'totp' => TwoFactor::currentCode($setup->secret),
        'recovery' => $setup->recoveryCodes[0],
        'wrong' => '000000',
        'malformed' => 'not-a-code',
    };

    // Pinned to the expected outcome too, so two equally broken answers cannot agree.
    expect(TwoFactor::attempt($a, $code($setupA))->verified)->toBe($expected)
        ->and(TwoFactor::verifyFor($b, $code($setupB)))->toBe($expected);

    Carbon::setTestNow();
})->with([
    'totp' => ['totp', true],
    'recovery code' => ['recovery', true],
    'wrong code' => ['wrong', false],
    'malformed code' => ['malformed', false],
]);
