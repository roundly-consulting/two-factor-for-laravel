<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\Otp\InvalidOtpParameterException;
use RoundlyConsulting\Crypto\Otp\ProvisioningUri;
use RoundlyConsulting\Crypto\Otp\Totp;
use RoundlyConsulting\Crypto\Random\Secret;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorService;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidBase32Exception;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorConfigException;
use RoundlyConsulting\TwoFactor\Support\ConfigGuard;
use RoundlyConsulting\TwoFactor\Support\RecoveryCodeManager;
use SensitiveParameter;

/**
 * The real {@see TwoFactorService}, bound as the `TwoFactor` facade root: the TOTP
 * primitives, plus `for($user)`, whose handle resolves each use case's action from
 * the container.
 *
 * The OTP maths, the base32 codec and the CSPRNG all come from
 * crypto-for-laravel. This class is the boundary: it builds those primitives
 * from this package's own config and translates every crypto failure back into
 * the two-factor exception a host already catches.
 */
final readonly class TwoFactorManager implements TwoFactorService
{
    public function __construct(
        private Container $container,
    ) {}

    public function for(TwoFactorAuthenticatable&Model $user): UserTwoFactor
    {
        return new UserTwoFactor($this->container, $user);
    }

    /**
     * A fresh base32 secret backed by the CSPRNG.
     *
     * @throws InvalidTwoFactorConfigException when the length is out of range
     */
    public function generateSecret(?int $length = null): string
    {
        $length ??= ConfigGuard::secretLength();

        // Bound an explicit caller length by the same rule as the configured one,
        // so no path can mint a secret below the package's entropy floor.
        return Secret::base32(ConfigGuard::assertSecretLength($length));
    }

    /**
     * @throws InvalidBase32Exception when the secret is not valid base32
     */
    public function currentCode(#[SensitiveParameter] string $secret, ?int $timestamp = null): string
    {
        try {
            return $this->totp()->codeAt($secret, $timestamp);
        } catch (InvalidEncodingException $e) {
            throw InvalidBase32Exception::fromCodec($e);
        }
    }

    /**
     * @return int|false the matched timestep, or false
     *
     * @throws InvalidBase32Exception when the secret is not valid base32
     * @throws InvalidTwoFactorConfigException when the window is out of range
     */
    public function verify(
        #[SensitiveParameter] string $secret,
        #[SensitiveParameter] string $code,
        ?int $window = null,
    ): int|false {
        $window ??= ConfigGuard::window();

        try {
            return $this->totp()->verify($secret, $code, $window);
        } catch (InvalidEncodingException $e) {
            throw InvalidBase32Exception::fromCodec($e);
        } catch (InvalidOtpParameterException) {
            // The only parameter the caller can still push out of range here is
            // the explicit window; digits/period came through ConfigGuard.
            throw InvalidTwoFactorConfigException::window($window);
        }
    }

    public function provisioningUri(
        #[SensitiveParameter] string $secret,
        string $label,
        ?string $issuer = null,
    ): string {
        return ProvisioningUri::totp(
            $secret,
            $label,
            ConfigGuard::issuer($issuer),
            ConfigGuard::algorithm(),
            ConfigGuard::digits(),
            ConfigGuard::period(),
        );
    }

    /**
     * @return list<string>
     */
    public function generateRecoveryCodes(?int $count = null): array
    {
        $count ??= ConfigGuard::recoveryCodeCount();

        return (new RecoveryCodeManager(
            ConfigGuard::recoveryCodeStorage(),
        ))->generate($count);
    }

    /**
     * The OTP primitive, parameterised from this package's own config. Crypto is
     * zero-config: every knob is passed in here, bounds-checked first.
     */
    private function totp(): Totp
    {
        return new Totp(
            ConfigGuard::algorithm(),
            ConfigGuard::digits(),
            ConfigGuard::period(),
        );
    }
}
