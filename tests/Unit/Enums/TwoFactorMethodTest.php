<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\Enums\TwoFactorMethod;

it('exposes the two backed methods', function (): void {
    // The values are a wire contract (an `amr` claim, an audit column): pin them.
    expect(TwoFactorMethod::values()->all())->toBe(['totp', 'recovery_code']);
});

it('resolves from its stored value', function (): void {
    expect(TwoFactorMethod::from('recovery_code'))->toBe(TwoFactorMethod::RecoveryCode)
        ->and(TwoFactorMethod::tryFrom('sms'))->toBeNull();
});
