<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\Facades\TwoFactor;
use RoundlyConsulting\TwoFactor\Support\Base32;

it('generates a base32 secret of the configured length', function (): void {
    $secret = TwoFactor::generateSecret();

    expect($secret)->toHaveLength(16)
        ->and(Base32::decode($secret))->not->toBe(''); // decodes cleanly
});

it('honours an explicit secret length', function (): void {
    expect(TwoFactor::generateSecret(32))->toHaveLength(32);
});

it('generates distinct secrets', function (): void {
    expect(TwoFactor::generateSecret())->not->toBe(TwoFactor::generateSecret());
});

it('verifies its own current code', function (): void {
    $secret = TwoFactor::generateSecret();

    expect(TwoFactor::verify($secret, TwoFactor::currentCode($secret)))->not->toBeFalse();
});

it('generates the configured number of recovery codes', function (): void {
    expect(TwoFactor::generateRecoveryCodes())->toHaveCount(8)
        ->and(TwoFactor::generateRecoveryCodes(3))->toHaveCount(3);
});
