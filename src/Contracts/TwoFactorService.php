<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Contracts;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\TwoFactorManager;
use RoundlyConsulting\TwoFactor\UserTwoFactor;
use SensitiveParameter;

/**
 * The package's public API and the `TwoFactor` facade root: the stateless TOTP
 * primitives, plus `for($user)` for everything that reads or changes one user's
 * two-factor state. Inject this contract — `TwoFactor::fake()` swaps the
 * container binding, so constructor-injected code sees the fake too. The real
 * implementation is {@see TwoFactorManager}.
 */
interface TwoFactorService
{
    /**
     * One user's two-factor: start, confirm, attempt, status, recovery codes, disable.
     */
    public function for(TwoFactorAuthenticatable&Model $user): UserTwoFactor;

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
