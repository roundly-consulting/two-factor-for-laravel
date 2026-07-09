<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Contracts;

use Illuminate\Database\Eloquent\Model;
use SensitiveParameter;

/**
 * The package's public verification surface. Extracted so the concrete service
 * (which stays final) can be substituted by the shipped FakeTwoFactor in tests
 * via TwoFactor::fake(); the real service and every Action bind this contract.
 */
interface TwoFactorService
{
    public function generateSecret(?int $length = null): string;

    public function currentCode(#[SensitiveParameter] string $secret, ?int $timestamp = null): string;

    /**
     * @return int|false the matched timestep, or false
     */
    public function verify(
        #[SensitiveParameter] string $secret,
        #[SensitiveParameter] string $code,
        ?int $window = null,
    ): int|false;

    public function verifyFor(TwoFactorAuthenticatable&Model $user, #[SensitiveParameter] string $code): bool;

    public function provisioningUri(
        #[SensitiveParameter] string $secret,
        string $label,
        ?string $issuer = null,
    ): string;

    /**
     * @return list<string>
     */
    public function generateRecoveryCodes(?int $count = null): array;
}
