<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\Enums\RecoveryCodeStorage;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorConfigException;

it('maps each mode to its eloquent cast', function (): void {
    expect(RecoveryCodeStorage::Encrypted->cast())->toBe('encrypted:array')
        ->and(RecoveryCodeStorage::Hashed->cast())->toBe('array');
});

it('resolves a valid config string', function (): void {
    expect(RecoveryCodeStorage::fromConfig('hashed'))->toBe(RecoveryCodeStorage::Hashed);
});

it('throws on an unsupported storage mode', function (): void {
    RecoveryCodeStorage::fromConfig('plaintext');
})->throws(InvalidTwoFactorConfigException::class);

it('exposes the enums-for-laravel helpers surface', function (): void {
    expect(RecoveryCodeStorage::values()->all())->toBe(['encrypted', 'hashed']);
});
