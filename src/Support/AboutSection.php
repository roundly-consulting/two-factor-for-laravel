<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Support;

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
            'Algorithm' => (string) config('two-factor.algorithm'),
            'Code' => sprintf(
                '%d digits every %ds',
                (int) config('two-factor.digits', 6),
                (int) config('two-factor.period', 30),
            ),
            'Drift window' => sprintf('±%d timesteps', (int) config('two-factor.window', 1)),
            'Secret length' => sprintf('%d base32 chars', (int) config('two-factor.secret_length', 32)),
            'Issuer' => config('two-factor.issuer') === null ? 'DEFAULT (app.name)' : 'SET',
            'Recovery codes' => sprintf(
                '%d %s codes',
                (int) config('two-factor.recovery_codes.count', 8),
                (string) config('two-factor.recovery_codes.storage'),
            ),
            'Replay guard' => self::replayGuard(),
            'Attempt limit' => self::attemptLimit(),
            'Columns' => self::columns(),
        ];
    }

    private static function replayGuard(): string
    {
        $mode = config('two-factor.replay_guard');

        if ($mode === null || $mode === 'none') {
            return 'OFF';
        }

        if ($mode === 'cache') {
            // The store's *name* stays out of the output (the jwt secret-safe rule).
            return config('two-factor.cache.store') === null
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
            (int) config('two-factor.attempts.max', 5),
            (int) config('two-factor.attempts.decay', 60),
        );
    }

    private static function columns(): string
    {
        $columns = config('two-factor.columns');

        $default = [
            'secret' => 'two_factor_secret',
            'recovery_codes' => 'two_factor_recovery_codes',
            'confirmed_at' => 'two_factor_confirmed_at',
            'last_used_timestep' => 'two_factor_last_used_timestep',
        ];

        return $columns === $default ? 'default' : 'remapped';
    }
}
