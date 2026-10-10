<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Facades;

use Illuminate\Support\Facades\Facade;
use RoundlyConsulting\PackageToolkit\Concerns\RedactsSensitiveArguments;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorService;
use RoundlyConsulting\TwoFactor\Testing\TwoFactorFake;
use RoundlyConsulting\TwoFactor\TwoFactorManager;

/**
 * @method static \RoundlyConsulting\TwoFactor\UserTwoFactor for(\RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable&\Illuminate\Database\Eloquent\Model $user)
 * @method static string generateSecret(?int $length = null)
 * @method static string currentCode(string $secret, ?int $timestamp = null)
 * @method static int|false verify(string $secret, string $code, ?int $window = null)
 * @method static string provisioningUri(string $secret, string $label, ?string $issuer = null)
 * @method static list<string> generateRecoveryCodes(?int $count = null)
 *
 * @see TwoFactorService
 * @see TwoFactorManager
 */
final class TwoFactor extends Facade
{
    use RedactsSensitiveArguments;

    /**
     * Swap the two-factor service for a programmable, no-crypto recording fake
     * (bound under the service contract) and return it for assertions.
     */
    public static function fake(): TwoFactorFake
    {
        $fake = app(TwoFactorFake::class);

        self::swap($fake);

        return $fake;
    }

    protected static function getFacadeAccessor(): string
    {
        return TwoFactorService::class;
    }
}
