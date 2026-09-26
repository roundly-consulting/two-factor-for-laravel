<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Support;

use RoundlyConsulting\Crypto\Otp\OtpAlgorithm;
use RoundlyConsulting\Crypto\Random\Secret;
use RoundlyConsulting\TwoFactor\DataTransferObjects\AttemptLimit;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorConfigException;

/**
 * Reads and bounds-checks the security-sensitive TOTP config so a misconfigured
 * host fails loudly rather than silently degrading to near-useless 2FA (a
 * ±15-minute window, a 4-digit code space, an empty secret, and so on).
 *
 * These bounds are deliberately tighter than the ones crypto-for-laravel itself
 * enforces, so a value this guard accepts is always a value the OTP primitives
 * accept — the package's own InvalidTwoFactorConfigException stays the single
 * failure mode a host has to catch.
 */
final class ConfigGuard
{
    /**
     * The configured HMAC algorithm, as the OTP primitive's enum.
     *
     * The backing values are the same three strings the package has always
     * accepted ('sha1' | 'sha256' | 'sha512'), so a host's existing config keeps
     * its exact meaning.
     *
     * @throws InvalidTwoFactorConfigException on an unsupported value, rather than
     *                                         silently downgrading the hash
     */
    public static function algorithm(): OtpAlgorithm
    {
        $value = (string) config('two-factor.algorithm');

        return OtpAlgorithm::tryFrom($value)
            ?? throw InvalidTwoFactorConfigException::algorithm($value);
    }

    public static function digits(): int
    {
        $digits = (int) config('two-factor.digits', 6);

        if ($digits < 6 || $digits > 8) {
            throw InvalidTwoFactorConfigException::digits($digits);
        }

        return $digits;
    }

    public static function period(): int
    {
        $period = (int) config('two-factor.period', 30);

        if ($period < 15 || $period > 120) {
            throw InvalidTwoFactorConfigException::period($period);
        }

        return $period;
    }

    public static function window(): int
    {
        $window = (int) config('two-factor.window', 1);

        if ($window < 0 || $window > 2) {
            throw InvalidTwoFactorConfigException::window($window);
        }

        return $window;
    }

    public static function secretLength(): int
    {
        return self::assertSecretLength((int) config('two-factor.secret_length', 32));
    }

    /**
     * Bound a secret length — from config or from an explicit caller argument —
     * before it reaches the generator, so an out-of-range length always surfaces
     * as this package's config exception.
     */
    public static function assertSecretLength(int $length): int
    {
        if ($length < 16) {
            throw InvalidTwoFactorConfigException::secretLength($length);
        }

        if ($length > Secret::MAXIMUM_CHARS) {
            throw InvalidTwoFactorConfigException::secretLengthTooLong($length, Secret::MAXIMUM_CHARS);
        }

        return $length;
    }

    /**
     * The resolved brute-force limiter, or null when the host disables it (a null
     * `attempts` config) to run its own throttling middleware instead.
     */
    public static function attemptLimit(): ?AttemptLimit
    {
        if (config('two-factor.attempts') === null) {
            return null;
        }

        $max = (int) config('two-factor.attempts.max', 5);
        $decay = (int) config('two-factor.attempts.decay', 60);

        if ($max < 1) {
            throw InvalidTwoFactorConfigException::attempts('max', $max);
        }

        if ($decay < 1) {
            throw InvalidTwoFactorConfigException::attempts('decay', $decay);
        }

        return new AttemptLimit($max, $decay);
    }

    /**
     * The default provisioning issuer: `two-factor.issuer`, else the app name.
     * A caller-supplied issuer (per guard, per tenant) always wins over this.
     */
    public static function issuer(): string
    {
        return (string) (config('two-factor.issuer') ?? config('app.name'));
    }
}
