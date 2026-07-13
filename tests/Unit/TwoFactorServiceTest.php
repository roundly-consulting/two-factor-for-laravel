<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use RoundlyConsulting\Crypto\Codec\Base32;
use RoundlyConsulting\Crypto\Otp\OtpAlgorithm;
use RoundlyConsulting\Crypto\Otp\Totp;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidBase32Exception;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorConfigException;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;

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
