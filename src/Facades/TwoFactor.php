<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Facades;

use Illuminate\Support\Facades\Facade;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorService;
use RoundlyConsulting\TwoFactor\Testing\FakeTwoFactor;

/**
 * @method static string generateSecret(?int $length = null)
 * @method static string currentCode(string $secret, ?int $timestamp = null)
 * @method static int|false verify(string $secret, string $code, ?int $window = null)
 * @method static \RoundlyConsulting\TwoFactor\DataTransferObjects\VerificationResult attempt(\RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable&\Illuminate\Database\Eloquent\Model $user, string $code)
 * @method static bool verifyFor(\RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable&\Illuminate\Database\Eloquent\Model $user, string $code)
 * @method static string provisioningUri(string $secret, string $label, ?string $issuer = null)
 * @method static list<string> generateRecoveryCodes(?int $count = null)
 *
 * @see TwoFactorService
 */
final class TwoFactor extends Facade
{
    /**
     * Swap the two-factor service for a programmable, no-crypto recording fake
     * (bound under the service contract) and return it for assertions.
     */
    public static function fake(): FakeTwoFactor
    {
        $fake = new FakeTwoFactor;

        self::swap($fake);
        self::getFacadeApplication()->instance(TwoFactorService::class, $fake);

        return $fake;
    }

    protected static function getFacadeAccessor(): string
    {
        return TwoFactorService::class;
    }
}
