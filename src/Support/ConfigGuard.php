<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Support;

use RoundlyConsulting\Crypto\Otp\OtpAlgorithm;
use RoundlyConsulting\Crypto\Random\Secret;
use RoundlyConsulting\PackageToolkit\Support\Config;
use RoundlyConsulting\TwoFactor\DataTransferObjects\AttemptLimit;
use RoundlyConsulting\TwoFactor\Enums\RecoveryCodeStorage;
use RoundlyConsulting\TwoFactor\Enums\ReplayGuardMode;
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
 *
 * Every read is strict: a key that is not set — absent, null or blank (`''` or
 * whitespace, a host's `KEY=`) — takes its default, but a present value of the
 * wrong shape — `'five'`, `'1.5'`, an unknown enum value, a non-string column
 * name — throws InvalidTwoFactorConfigException naming the key. A typo never
 * quietly becomes a 0-step window or a default column.
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
        $value = self::set(config('two-factor.algorithm')) ?? OtpAlgorithm::Sha1->value;

        if ($value instanceof OtpAlgorithm) {
            return $value;
        }

        return (is_string($value) ? OtpAlgorithm::tryFrom($value) : null)
            ?? throw InvalidTwoFactorConfigException::algorithm(is_scalar($value) ? (string) $value : get_debug_type($value));
    }

    public static function digits(): int
    {
        $digits = self::integer('two-factor.digits', config('two-factor.digits'), 6);

        if ($digits < 6 || $digits > 8) {
            throw InvalidTwoFactorConfigException::digits($digits);
        }

        return $digits;
    }

    public static function period(): int
    {
        $period = self::integer('two-factor.period', config('two-factor.period'), 30);

        if ($period < 15 || $period > 120) {
            throw InvalidTwoFactorConfigException::period($period);
        }

        return $period;
    }

    public static function window(): int
    {
        $window = self::integer('two-factor.window', config('two-factor.window'), 1);

        if ($window < 0 || $window > 2) {
            throw InvalidTwoFactorConfigException::window($window);
        }

        return $window;
    }

    public static function secretLength(): int
    {
        return self::assertSecretLength(self::integer('two-factor.secret_length', config('two-factor.secret_length'), 32));
    }

    /**
     * Bound a secret length — from config or from an explicit caller argument —
     * before it reaches the generator, so an out-of-range length always surfaces
     * as this package's config exception.
     *
     * Every length in range works: one no base32 string can have (1, 3 or 6
     * mod 8) is rounded up one character by crypto's Secret::base32(), so the
     * secret always decodes and never carries less entropy than asked for.
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
     * `attempts` config) to run its own throttling middleware instead. A blank
     * value is not set, so the shipped limits apply.
     */
    public static function attemptLimit(): ?AttemptLimit
    {
        $attempts = config('two-factor.attempts');

        if ($attempts === null) {
            return null;
        }

        // `false`, `'off'` or `0` is not how the limiter is switched off — only null is.
        if (! is_array($attempts) && self::set($attempts) !== null) {
            throw InvalidTwoFactorConfigException::attemptsShape(get_debug_type($attempts));
        }

        $max = self::integer('two-factor.attempts.max', config('two-factor.attempts.max'), 5);
        $decay = self::integer('two-factor.attempts.decay', config('two-factor.attempts.decay'), 60);

        if ($max < 1) {
            throw InvalidTwoFactorConfigException::attempts('max', $max);
        }

        if ($decay < 1) {
            throw InvalidTwoFactorConfigException::attempts('decay', $decay);
        }

        return new AttemptLimit($max, $decay);
    }

    /**
     * The provisioning issuer: the caller's (per guard, per tenant), else
     * `two-factor.issuer`, else the app name. A blank value at either level counts
     * as unset — `TWO_FACTOR_ISSUER=` in a .env is an empty string, not null, and
     * must not brand every authenticator entry with an empty issuer. A configured
     * issuer that is not a string at all throws.
     */
    public static function issuer(?string $override = null): string
    {
        $configured = config('two-factor.issuer');

        if ($configured !== null && ! is_string($configured)) {
            throw InvalidTwoFactorConfigException::notAString('two-factor.issuer', $configured);
        }

        foreach ([$override, $configured] as $candidate) {
            if (is_string($candidate) && trim($candidate) !== '') {
                return $candidate;
            }
        }

        return (string) config('app.name');
    }

    /**
     * How many recovery codes a fresh set holds (at least one).
     */
    public static function recoveryCodeCount(): int
    {
        return self::integer('two-factor.recovery_codes.count', config('two-factor.recovery_codes.count'), 8, min: 1);
    }

    /**
     * The recovery-code storage mode; `hashed` when absent, and an unknown mode throws
     * rather than silently changing how the codes are kept at rest.
     */
    public static function recoveryCodeStorage(): RecoveryCodeStorage
    {
        return RecoveryCodeStorage::fromConfig(self::set(config('two-factor.recovery_codes.storage')) ?? RecoveryCodeStorage::Hashed->value);
    }

    /**
     * The replay-guard mode; null (or `none`) switches replay protection off, and a
     * blank value is not set, so the shipped `column` guard applies.
     */
    public static function replayGuard(): ReplayGuardMode
    {
        return ReplayGuardMode::fromConfig(config('two-factor.replay_guard'));
    }

    /**
     * The cache store the cache replay guard writes to; null (or blank) is the default store.
     */
    public static function cacheStore(): ?string
    {
        $store = config('two-factor.cache.store');

        if ($store !== null && ! is_string($store)) {
            throw InvalidTwoFactorConfigException::notAString('two-factor.cache.store', $store);
        }

        return $store === null || trim($store) === '' ? null : $store;
    }

    /**
     * Seconds the cache replay guard keeps the last used timestep (at least one).
     */
    public static function cacheTtl(): int
    {
        return self::integer('two-factor.cache.ttl', config('two-factor.cache.ttl'), 86_400, min: 1);
    }

    /**
     * The table the published migration alters (`two-factor.table`, `users` when absent).
     */
    public static function table(): string
    {
        return self::name('two-factor.table', config('two-factor.table'), 'users');
    }

    /**
     * The four two-factor column names on the account table, each `two-factor.columns.*`
     * or its default when not set (absent, null or blank). A non-string name throws.
     *
     * @return array{secret: string, recovery_codes: string, confirmed_at: string, last_used_timestep: string}
     */
    public static function columns(): array
    {
        $columns = config('two-factor.columns');

        if (self::set($columns) !== null && ! is_array($columns)) {
            throw InvalidTwoFactorConfigException::notAString('two-factor.columns', $columns);
        }

        return [
            'secret' => self::name('two-factor.columns.secret', config('two-factor.columns.secret'), 'two_factor_secret'),
            'recovery_codes' => self::name('two-factor.columns.recovery_codes', config('two-factor.columns.recovery_codes'), 'two_factor_recovery_codes'),
            'confirmed_at' => self::name('two-factor.columns.confirmed_at', config('two-factor.columns.confirmed_at'), 'two_factor_confirmed_at'),
            'last_used_timestep' => self::name('two-factor.columns.last_used_timestep', config('two-factor.columns.last_used_timestep'), 'two_factor_last_used_timestep'),
        ];
    }

    /**
     * A strict integer: the default when not set (absent, null or blank); anything
     * but an int or a canonical integer string throws (a `'five'` window must not
     * read as 0).
     */
    private static function integer(string $key, mixed $value, int $default, ?int $min = null): int
    {
        return Config::for([$key => $value], InvalidTwoFactorConfigException::class)->integer($key, $default, $min);
    }

    /**
     * A table or column name: the default when not set (absent, null or blank); a
     * non-string throws.
     */
    private static function name(string $key, mixed $value, string $default): string
    {
        $value = self::set($value) ?? $default;

        if (! is_string($value)) {
            throw InvalidTwoFactorConfigException::notAString($key, $value);
        }

        return $value;
    }

    /**
     * The value, or null when it is not set: a blank string (`''` or whitespace —
     * what a host's `KEY=` puts in config) means the same as an absent key.
     */
    private static function set(mixed $value): mixed
    {
        return is_string($value) && trim($value) === '' ? null : $value;
    }
}
