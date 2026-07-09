<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\Facades\TwoFactor;

it('builds a parseable otpauth uri with encoded label and issuer', function (): void {
    config(['two-factor.issuer' => 'Acme Corp']);

    $uri = TwoFactor::provisioningUri('JBSWY3DPEHPK3PXP', 'user+tag@acme.io');

    expect($uri)->toStartWith('otpauth://totp/Acme%20Corp:user%2Btag%40acme.io?');

    $query = [];
    parse_str((string) parse_url($uri, PHP_URL_QUERY), $query);

    expect($query['secret'])->toBe('JBSWY3DPEHPK3PXP')
        ->and($query['issuer'])->toBe('Acme Corp')
        ->and($query['algorithm'])->toBe('SHA1')
        ->and($query['digits'])->toBe('6')
        ->and($query['period'])->toBe('30');
});

it('falls back to the app name when no issuer is configured', function (): void {
    config(['two-factor.issuer' => null, 'app.name' => 'Fallback App']);

    $uri = TwoFactor::provisioningUri('JBSWY3DPEHPK3PXP', 'user@acme.io');

    expect($uri)->toStartWith('otpauth://totp/Fallback%20App:');
});

it('reflects a non-default algorithm and digit count', function (): void {
    config(['two-factor.algorithm' => 'sha256', 'two-factor.digits' => 8]);

    $query = [];
    parse_str((string) parse_url(
        TwoFactor::provisioningUri('JBSWY3DPEHPK3PXP', 'user@acme.io', 'Acme'),
        PHP_URL_QUERY,
    ), $query);

    expect($query['algorithm'])->toBe('SHA256')
        ->and($query['digits'])->toBe('8');
});
