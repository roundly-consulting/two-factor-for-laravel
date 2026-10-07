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

/**
 * No base32 string is 1, 3 or 6 characters long (mod 8): its last character would
 * carry bits of no byte, and the strict codec rejects it. Such a length used to be
 * minted as asked and then fail every verify() — crypto's Secret::base32 now rounds
 * it UP one character, which keeps at least the requested entropy.
 */
it('mints a working secret for every allowed length', function (int $length): void {
    $secret = TwoFactor::generateSecret($length);
    $expected = in_array($length % 8, [1, 3, 6], true) ? $length + 1 : $length;

    expect($secret)->toHaveLength($expected)
        ->and(TwoFactor::verify($secret, TwoFactor::currentCode($secret)))->not->toBeFalse();
})->with(range(16, 40));

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

/**
 * RFC 6238 Appendix B, end to end through this package's own config (8 digits, each
 * algorithm with its seed) — not just crypto's primitive in isolation.
 */
it('reproduces every RFC 6238 Appendix B vector through the facade', function (string $algorithm, int $timestamp, string $expected): void {
    $seeds = [
        'sha1' => '12345678901234567890',
        'sha256' => '12345678901234567890123456789012',
        'sha512' => '1234567890123456789012345678901234567890123456789012345678901234',
    ];

    config(['two-factor.digits' => 8, 'two-factor.algorithm' => $algorithm]);
    $secret = Base32::encode($seeds[$algorithm]);

    expect(TwoFactor::currentCode($secret, $timestamp))->toBe($expected);

    Carbon::setTestNow(Carbon::createFromTimestamp($timestamp));
    expect(TwoFactor::verify($secret, $expected, 0))->toBe(intdiv($timestamp, 30));
    Carbon::setTestNow();
})->with([
    ['sha1', 59, '94287082'], ['sha256', 59, '46119246'], ['sha512', 59, '90693936'],
    ['sha1', 1111111109, '07081804'], ['sha256', 1111111109, '68084774'], ['sha512', 1111111109, '25091201'],
    ['sha1', 1111111111, '14050471'], ['sha256', 1111111111, '67062674'], ['sha512', 1111111111, '99943326'],
    ['sha1', 1234567890, '89005924'], ['sha256', 1234567890, '91819424'], ['sha512', 1234567890, '93441116'],
    ['sha1', 2000000000, '69279037'], ['sha256', 2000000000, '90698825'], ['sha512', 2000000000, '38618901'],
    ['sha1', 20000000000, '65353130'], ['sha256', 20000000000, '77737706'], ['sha512', 20000000000, '47863826'],
]);

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

/**
 * The exception says "expected 0–2", so an explicit window has to be bound by that same
 * rule, like an explicit secret length. Crypto alone accepts up to 10 steps (±5 minutes).
 */
it('bounds an explicit window by the same 0–2 rule as the configured one', function (int $window): void {
    $secret = testSecret();
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));

    expect(fn (): int|false => TwoFactor::verify($secret, TwoFactor::currentCode($secret, 1_700_000_000 - 150), $window))
        ->toThrow(InvalidTwoFactorConfigException::class, "({$window})");

    Carbon::setTestNow();
})->with([3, 5, 10, -1]);

it('honours an explicit window inside the bound', function (): void {
    $secret = testSecret();
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));

    expect(TwoFactor::verify($secret, TwoFactor::currentCode($secret, 1_700_000_000 - 60), 2))->toBe(56_666_664)
        ->and(TwoFactor::verify($secret, TwoFactor::currentCode($secret, 1_700_000_000 - 60), 0))->toBeFalse();

    Carbon::setTestNow();
});

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

    $result = TwoFactor::for($user)->attempt(TwoFactor::currentCode($setup->secret));

    expect($result)->toBeInstanceOf(VerificationResult::class)
        ->verified->toBeTrue()
        ->method->toBe(TwoFactorMethod::Totp)
        ->remainingRecoveryCodes->toBe(8)
        ->replayed->toBeFalse();

    Carbon::setTestNow();
});

it('attempts a recovery code and reports one fewer remaining', function (): void {
    [$user, $setup] = attemptableUser();

    expect(TwoFactor::for($user)->attempt($setup->recoveryCodes[0]))
        ->verified->toBeTrue()
        ->method->toBe(TwoFactorMethod::RecoveryCode)
        ->remainingRecoveryCodes->toBe(7)
        ->replayed->toBeFalse();

    expect(TwoFactor::for($user->fresh())->attempt($setup->recoveryCodes[1]))
        ->remainingRecoveryCodes->toBe(6);
});

it('reports a replayed timestep as a failure flagged replayed', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    [$user, $setup] = attemptableUser();
    $code = TwoFactor::currentCode($setup->secret);

    expect(TwoFactor::for($user)->attempt($code)->verified)->toBeTrue();

    expect(TwoFactor::for($user->fresh())->attempt($code))
        ->verified->toBeFalse()
        ->method->toBeNull()
        ->replayed->toBeTrue()
        ->remainingRecoveryCodes->toBe(8);

    Carbon::setTestNow();
});

it('reports a wrong code as a plain failure', function (): void {
    [$user] = attemptableUser();

    expect(TwoFactor::for($user)->attempt('000000'))
        ->verified->toBeFalse()
        ->method->toBeNull()
        ->replayed->toBeFalse()
        ->remainingRecoveryCodes->toBe(8);
});

it('fails a pending enrolment even with its valid code', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    $user = TwoFactorUser::factory()->create();
    $setup = app(StartEnrolment::class)->execute($user);

    expect(TwoFactor::for($user->fresh())->attempt(TwoFactor::currentCode($setup->secret)))
        ->verified->toBeFalse()
        ->method->toBeNull()
        ->remainingRecoveryCodes->toBe(8);

    Carbon::setTestNow();
});

it('fails a user with no enrolment at all', function (): void {
    expect(TwoFactor::for(TwoFactorUser::factory()->create())->attempt('123456'))
        ->verified->toBeFalse()
        ->remainingRecoveryCodes->toBe(0);
});

it('throws once the per-user limiter is exhausted', function (): void {
    config(['two-factor.attempts' => ['max' => 2, 'decay' => 60]]);
    [$user] = attemptableUser();

    TwoFactor::for($user)->attempt('000000');
    TwoFactor::for($user)->attempt('000000');

    TwoFactor::for($user)->attempt('000000');
})->throws(TwoFactorRateLimitedException::class);

it('agrees with the model verb for every outcome', function (string $kind, bool $expected): void {
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
    expect(TwoFactor::for($a)->attempt($code($setupA))->verified)->toBe($expected)
        ->and($b->verifyTwoFactorCode($code($setupB)))->toBe($expected);

    Carbon::setTestNow();
})->with([
    'totp' => ['totp', true],
    'recovery code' => ['recovery', true],
    'wrong code' => ['wrong', false],
    'malformed code' => ['malformed', false],
]);
