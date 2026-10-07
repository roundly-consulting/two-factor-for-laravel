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
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorSecretException;
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
     * @throws InvalidTwoFactorSecretException when the secret is no usable key
     */
    public function currentCode(#[SensitiveParameter] string $secret, ?int $timestamp = null): string
    {
        try {
            return $this->totp()->codeAt($secret, $timestamp);
        } catch (InvalidEncodingException $e) {
            throw InvalidBase32Exception::fromCodec($e);
        } catch (InvalidOtpParameterException $e) {
            throw InvalidTwoFactorSecretException::fromOtp($e);
        }
    }

    /**
     * @return int|false the matched timestep, or false
     *
     * @throws InvalidBase32Exception when the secret is not valid base32
     * @throws InvalidTwoFactorSecretException when the secret is no usable key
     * @throws InvalidTwoFactorConfigException when the window is out of range
     */
    public function verify(
        #[SensitiveParameter] string $secret,
        #[SensitiveParameter] string $code,
        ?int $window = null,
    ): int|false {
        // Bound an explicit caller window by the same rule as the configured one.
        $window = $window === null ? ConfigGuard::window() : ConfigGuard::assertWindow($window);

        try {
            return $this->totp()->verify($secret, $code, $window);
        } catch (InvalidEncodingException $e) {
            throw InvalidBase32Exception::fromCodec($e);
        } catch (InvalidOtpParameterException $e) {
            // Window, digits and period are all bounded by ConfigGuard before they
            // get here, so whatever the primitive still refuses is the secret.
            throw InvalidTwoFactorSecretException::fromOtp($e);
        }
    }

    /**
     * @throws InvalidBase32Exception when the secret is not valid base32
     * @throws InvalidTwoFactorSecretException when the secret is empty
     */
    public function provisioningUri(
        #[SensitiveParameter] string $secret,
        string $label,
        ?string $issuer = null,
    ): string {
        $issuer = ConfigGuard::issuer($issuer);
        $algorithm = ConfigGuard::algorithm();
        $digits = ConfigGuard::digits();
        $period = ConfigGuard::period();

        try {
            return ProvisioningUri::totp($secret, $label, $issuer, $algorithm, $digits, $period);
        } catch (InvalidEncodingException $e) {
            throw InvalidBase32Exception::fromCodec($e);
        } catch (InvalidOtpParameterException $e) {
            // Digits and period came through ConfigGuard: only the secret is left.
            throw InvalidTwoFactorSecretException::fromOtp($e);
        }
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
