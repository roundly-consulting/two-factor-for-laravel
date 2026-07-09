<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\Enums\HashAlgorithm;
use RoundlyConsulting\TwoFactor\Enums\RecoveryCodeStorage;

return [
    // TOTP parameters — defaults match google2fa / standard authenticator apps.
    'algorithm' => HashAlgorithm::Sha1->value,   // 'sha1' | 'sha256' | 'sha512'
    'digits' => 6,
    'period' => 30,                               // seconds per timestep
    'window' => 1,                                // accept ±N timesteps of drift
    'secret_length' => 16,                        // base32 chars

    // Provisioning (otpauth:// URI). issuer falls back to config('app.name') at runtime.
    'issuer' => env('TWO_FACTOR_ISSUER'),         // null → app.name

    'recovery_codes' => [
        'count' => 8,
        'storage' => RecoveryCodeStorage::Encrypted->value, // 'encrypted' (default) | 'hashed'
    ],

    // Replay protection: reject any code whose timestep <= the last successful one.
    'replay_guard' => 'column',                   // 'column' | 'cache' | null
    'cache' => [
        'store' => env('TWO_FACTOR_CACHE_STORE'), // null → default store (used by cache guard)
        'ttl' => 60 * 60 * 24,                    // seconds to retain last timestep in cache mode
    ],

    // Column names on the host users table — remap for non-standard schemas.
    'columns' => [
        'secret' => 'two_factor_secret',
        'recovery_codes' => 'two_factor_recovery_codes',
        'confirmed_at' => 'two_factor_confirmed_at',
        'last_used_timestep' => 'two_factor_last_used_timestep',
    ],
];
