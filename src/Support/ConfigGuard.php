<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Support;

use RoundlyConsulting\TwoFactor\DataTransferObjects\AttemptLimit;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorConfigException;

/**
 * Reads and bounds-checks the security-sensitive TOTP config so a misconfigured
 * host fails loudly rather than silently degrading to near-useless 2FA (a
 * ±15-minute window, a 4-digit code space, an empty secret, and so on).
 */
final class ConfigGuard
{
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
        $length = (int) config('two-factor.secret_length', 32);

        if ($length < 16) {
            throw InvalidTwoFactorConfigException::secretLength($length);
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
}
