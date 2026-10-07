<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Support;

use BackedEnum;
use RoundlyConsulting\PackageToolkit\Exceptions\InvalidConfigurationException;
use RoundlyConsulting\PackageToolkit\Support\Config;

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
 * would have explained the misconfiguration. A value the readers reject by type
 * — or, on a number row, a string that is not an integer (`'6abc'`, `'1.5'`) —
 * renders as `invalid (<type>)` on its row — never as the default, a cast number
 * or a believable presence report that would hide the misconfiguration.
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
                '%s digits every %s',
                self::integer('two-factor.digits', 6),
                self::integer('two-factor.period', 30, '%ds'),
            ),
            'Drift window' => self::integer('two-factor.window', 1, '±%d').' timesteps',
            'Secret length' => self::integer('two-factor.secret_length', 32).' base32 chars',
            'Issuer' => self::presence('two-factor.issuer', 'DEFAULT (app.name)', 'SET'),
            'Recovery codes' => sprintf(
                '%s %s codes',
                self::integer('two-factor.recovery_codes.count', 8),
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
            return sprintf('cache (%s store)', self::presence('two-factor.cache.store', 'default', 'custom'));
        }

        return self::display($mode);
    }

    private static function attemptLimit(): string
    {
        $attempts = config('two-factor.attempts');

        if ($attempts === null) {
            return 'OFF (host throttling)';
        }

        // Only null switches the limiter off; a blank is not set (the shipped limits),
        // and any other non-array — `false`, `'off'`, `0` — is one the reader rejects.
        if (! is_array($attempts) && self::raw('two-factor.attempts') !== null) {
            return self::invalid($attempts);
        }

        return sprintf(
            '%s attempts / %s lockout',
            self::integer('two-factor.attempts.max', 5),
            self::integer('two-factor.attempts.decay', 60, '%ds'),
        );
    }

    /**
     * The raw value, or null when it is not set — absent, null or blank (`''` or
     * whitespace, a host's `KEY=`) — so a blank key renders as its default here too.
     */
    private static function raw(string $key): mixed
    {
        $value = config($key);

        return is_string($value) && trim($value) === '' ? null : $value;
    }

    /**
     * {@see self::raw()} for an enum-backed key: an enum case (a documented config
     * value) reads as its backing value, the way ConfigGuard resolves it.
     */
    private static function value(string $key): mixed
    {
        $value = self::raw($key);

        return $value instanceof BackedEnum ? $value->value : $value;
    }

    /**
     * An integer setting, through `$format`: the default when not set, else the value
     * parsed by the very rule {@see ConfigGuard} reads it with — an int or a canonical
     * integer string. Anything that rule rejects (`'five'`, `'1.5'`, `'+5'`, an
     * overflow, a float, an array, ...) renders as the `invalid (<type>)` marker in
     * its place, never as a cast number. Range bounds stay out: an out-of-range number
     * renders as itself.
     */
    private static function integer(string $key, int $default, string $format = '%d'): string
    {
        $value = config($key);

        try {
            return sprintf($format, Config::for([$key => $value])->integer($key, $default));
        } catch (InvalidConfigurationException) {
            return self::invalid($value);
        }
    }

    private static function string(string $key, string $default): string
    {
        return self::display(self::value($key) ?? $default);
    }

    /**
     * A string setting whose value stays out of the output: `$unset` when not set,
     * `$set` for a string, the `invalid (<type>)` marker for anything else.
     */
    private static function presence(string $key, string $unset, string $set): string
    {
        $value = self::raw($key);

        return match (true) {
            $value === null => $unset,
            is_string($value) => $set,
            default => self::invalid($value),
        };
    }

    /**
     * A config value as text. One the readers reject by type — an array, an object,
     * a bool — renders as an `invalid (<type>)` marker: casting it would crash the
     * whole `about` command, and printing the default would hide the misconfiguration.
     */
    private static function display(mixed $value): string
    {
        return is_scalar($value) && ! is_bool($value)
            ? (string) $value
            : self::invalid($value);
    }

    private static function invalid(mixed $value): string
    {
        return 'invalid ('.get_debug_type($value).')';
    }

    private static function columns(): string
    {
        $map = config('two-factor.columns');

        if (! is_array($map) && self::raw('two-factor.columns') !== null) {
            return self::invalid($map);
        }

        $default = [
            'secret' => 'two_factor_secret',
            'recovery_codes' => 'two_factor_recovery_codes',
            'confirmed_at' => 'two_factor_confirmed_at',
            'last_used_timestep' => 'two_factor_last_used_timestep',
        ];

        $remapped = false;

        // Every name is checked before reporting a remap: an invalid one makes the
        // reader throw, so it outranks a valid remap elsewhere in the map.
        foreach ($default as $column => $name) {
            $value = self::raw("two-factor.columns.{$column}") ?? $name;

            if (! is_string($value)) {
                return self::invalid($value);
            }

            $remapped = $remapped || $value !== $name;
        }

        return $remapped ? 'remapped' : 'default';
    }
}
