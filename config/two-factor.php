<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Otp\OtpAlgorithm;
use RoundlyConsulting\TwoFactor\Enums\RecoveryCodeStorage;
use RoundlyConsulting\TwoFactor\Enums\ReplayGuardMode;

return [
    // TOTP parameters — defaults match standard authenticator apps (RFC 6238).
    // Bounds are enforced at runtime; out-of-range or non-integer values (e.g.
    // 'five') throw InvalidTwoFactorConfigException rather than silently weakening 2FA.
    'algorithm' => OtpAlgorithm::Sha1->value,     // 'sha1' | 'sha256' | 'sha512'
    'digits' => 6,                                // 6–8
    'period' => 30,                               // 15–120 seconds per timestep
    'window' => 1,                                // 0–2: accept ±N timesteps of drift
    'secret_length' => 32,                        // base32 chars (16–4096); 32 = 160 bits; 1/3/6 (mod 8) round up by one

    // Provisioning (otpauth:// URI). issuer falls back to config('app.name') at runtime.
    'issuer' => env('TWO_FACTOR_ISSUER'),         // null/blank → app.name

    'recovery_codes' => [
        'count' => 8,
        'storage' => RecoveryCodeStorage::Hashed->value, // 'hashed' (default) | 'encrypted'
    ],

    // Built-in brute-force limiter for attempt(), keyed per user. Set to null
    // to disable it and rely on your own throttle middleware instead.
    'attempts' => [
        'max' => 5,                               // failed attempts before lockout
        'decay' => 60,                            // seconds the lockout lasts
    ],

    // Replay protection: reject any code whose timestep <= the last successful one.
    'replay_guard' => ReplayGuardMode::Column->value, // 'column' | 'cache' | 'none' (null → none; blank → column)
    'cache' => [
        'store' => env('TWO_FACTOR_CACHE_STORE'), // null/blank → default store (used by cache guard)
        'ttl' => 60 * 60 * 24,                    // seconds to retain last timestep in cache mode (≥ (2 × window + 1) × period)
    ],

    // The table the published migration adds the columns to. Other account
    // tables get them via `$table->twoFactorColumns()` in your own migration.
    'table' => env('TWO_FACTOR_TABLE', 'users'),

    // Column names on the host account table(s) — remap for non-standard schemas.
    'columns' => [
        'secret' => 'two_factor_secret',
        'recovery_codes' => 'two_factor_recovery_codes',
        'confirmed_at' => 'two_factor_confirmed_at',
        'last_used_timestep' => 'two_factor_last_used_timestep',
    ],
];
