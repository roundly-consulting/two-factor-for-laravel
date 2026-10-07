<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Support;

use BackedEnum;

/**
 * The `php artisan about` payload for this package.
 *
 * Security posture: a 2FA package must never surface anything an attacker could
 * use. Nothing here renders a TOTP secret, a recovery code, the configured
 * issuer, or the cache store's name — only the security *parameters* (which are
 * public by construction: they travel in the otpauth:// URI), switches, counts,
 * and SET/DEFAULT presence.
 *
 * Values are read raw rather than through {@see ConfigGuard} so `about` still
 * renders on a misconfigured host instead of throwing at the diagnostic that
 * would have explained the misconfiguration.
 */
final class AboutSection
{
    /**
     * @return array<string, string>
     */
    public static function payload(): array
    {
        return [
            'Algorithm' => self::string('two-factor.algorithm', 'sha1'),
            'Code' => sprintf(
                '%d digits every %ds',
                self::int('two-factor.digits', 6),
                self::int('two-factor.period', 30),
            ),
            'Drift window' => sprintf('±%d timesteps', self::int('two-factor.window', 1)),
            'Secret length' => sprintf('%d base32 chars', self::int('two-factor.secret_length', 32)),
            'Issuer' => self::value('two-factor.issuer') === null ? 'DEFAULT (app.name)' : 'SET',
            'Recovery codes' => sprintf(
                '%d %s codes',
                self::int('two-factor.recovery_codes.count', 8),
                self::string('two-factor.recovery_codes.storage', 'hashed'),
            ),
            'Replay guard' => self::replayGuard(),
            'Attempt limit' => self::attemptLimit(),
            'Columns' => self::columns(),
        ];
    }

    private static function replayGuard(): string
    {
        if (config('two-factor.replay_guard') === null) {
            return 'OFF';
        }

        // Blank is not set: the shipped column guard, as ReplayGuardMode resolves it.
        $mode = self::value('two-factor.replay_guard') ?? 'column';

        if ($mode === 'none') {
            return 'OFF';
        }

        if ($mode === 'cache') {
            // The store's *name* stays out of the output (the jwt secret-safe rule).
            return self::value('two-factor.cache.store') === null
                ? 'cache (default store)'
                : 'cache (custom store)';
        }

        return (string) $mode;
    }

    private static function attemptLimit(): string
    {
        if (config('two-factor.attempts') === null) {
            return 'OFF (host throttling)';
        }

        return sprintf(
            '%d attempts / %ds lockout',
            self::int('two-factor.attempts.max', 5),
            self::int('two-factor.attempts.decay', 60),
        );
    }

    /**
     * The raw value, or null when it is not set — absent, null or blank (`''` or
     * whitespace, a host's `KEY=`) — so a blank key renders as its default here too.
     * An enum case (a documented config value) reads as its backing value, the way
     * ConfigGuard resolves it.
     */
    private static function value(string $key): mixed
    {
        $value = config($key);

        if ($value instanceof BackedEnum) {
            return $value->value;
        }

        return is_string($value) && trim($value) === '' ? null : $value;
    }

    private static function int(string $key, int $default): int
    {
        $value = self::value($key) ?? $default;

        return is_scalar($value) ? (int) $value : $default;
    }

    private static function string(string $key, string $default): string
    {
        $value = self::value($key) ?? $default;

        return is_scalar($value) ? (string) $value : $default;
    }

    private static function columns(): string
    {
        $default = [
            'secret' => 'two_factor_secret',
            'recovery_codes' => 'two_factor_recovery_codes',
            'confirmed_at' => 'two_factor_confirmed_at',
            'last_used_timestep' => 'two_factor_last_used_timestep',
        ];

        foreach ($default as $column => $name) {
            if ((self::value("two-factor.columns.{$column}") ?? $name) !== $name) {
                return 'remapped';
            }
        }

        return 'default';
    }
}
