<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\DataTransferObjects\VerificationResult;
use RoundlyConsulting\TwoFactor\Enums\TwoFactorMethod;

it('builds a success carrying the method and remaining count', function (): void {
    expect(VerificationResult::via(TwoFactorMethod::Totp, 8))
        ->verified->toBeTrue()
        ->method->toBe(TwoFactorMethod::Totp)
        ->remainingRecoveryCodes->toBe(8)
        ->replayed->toBeFalse();
});

it('builds a failure with no method', function (): void {
    expect(VerificationResult::failed(5))
        ->verified->toBeFalse()
        ->method->toBeNull()
        ->remainingRecoveryCodes->toBe(5)
        ->replayed->toBeFalse();
});

it('flags a replayed failure', function (): void {
    expect(VerificationResult::failed(5, replayed: true))
        ->verified->toBeFalse()
        ->method->toBeNull()
        ->replayed->toBeTrue();
});
