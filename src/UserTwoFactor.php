<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor;

use Carbon\CarbonImmutable;
use DateTimeInterface;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Actions\AttemptTwoFactorCode;
use RoundlyConsulting\TwoFactor\Actions\ConfirmEnrolment;
use RoundlyConsulting\TwoFactor\Actions\DisableTwoFactor;
use RoundlyConsulting\TwoFactor\Actions\StartEnrolment;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;
use RoundlyConsulting\TwoFactor\DataTransferObjects\TwoFactorSetup;
use RoundlyConsulting\TwoFactor\DataTransferObjects\TwoFactorStatus;
use RoundlyConsulting\TwoFactor\DataTransferObjects\VerificationResult;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorCodeException;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorAlreadyEnabledException;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorNotPendingException;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorRateLimitedException;
use RoundlyConsulting\TwoFactor\Support\ConfigGuard;
use SensitiveParameter;

/**
 * One user's two-factor, returned by `TwoFactor::for($user)`. Every write
 * resolves its action from the container, so host overrides and
 * `TwoFactor::fake()` apply; the `HasTwoFactorAuthentication` verbs route
 * through here too.
 *
 * Not final: the recording fake extends it.
 */
readonly class UserTwoFactor
{
    public function __construct(
        protected Container $container,
        protected TwoFactorAuthenticatable&Model $user,
    ) {}

    /**
     * Begin (or restart) a pending enrolment. Pass an issuer to brand the
     * authenticator entry per guard or tenant; null falls back to config.
     *
     * @throws TwoFactorAlreadyEnabledException
     */
    public function start(?string $label = null, ?string $issuer = null): TwoFactorSetup
    {
        return $this->container->make(StartEnrolment::class)->execute($this->user, $label, $issuer);
    }

    /**
     * Confirm the pending enrolment with the first authenticator code.
     *
     * @throws TwoFactorNotPendingException
     * @throws InvalidTwoFactorCodeException
     */
    public function confirm(#[SensitiveParameter] string $code): void
    {
        $this->container->make(ConfirmEnrolment::class)->execute($this->user, $code);
    }

    /**
     * Attempt a login-challenge code: TOTP with replay protection, then a
     * single-use recovery code.
     *
     * @throws TwoFactorRateLimitedException
     */
    public function attempt(#[SensitiveParameter] string $code): VerificationResult
    {
        return $this->container->make(AttemptTwoFactorCode::class)->execute($this->user, $code);
    }

    public function status(): TwoFactorStatus
    {
        $enabled = $this->user->hasTwoFactorEnabled();

        return new TwoFactorStatus(
            enabled: $enabled,
            pending: $this->user->hasPendingTwoFactor(),
            recoveryCodesRemaining: count($this->user->twoFactorRecoveryCodes()),
            confirmedAt: $enabled ? $this->confirmedAt() : null,
        );
    }

    public function recoveryCodes(): UserRecoveryCodes
    {
        return new UserRecoveryCodes($this->container, $this->user);
    }

    /**
     * Clear every two-factor column, fully disabling two-factor for the user.
     */
    public function disable(): void
    {
        $this->container->make(DisableTwoFactor::class)->execute($this->user);
    }

    private function confirmedAt(): ?CarbonImmutable
    {
        $value = $this->user->getAttribute(ConfigGuard::columns()['confirmed_at']);

        if ($value instanceof DateTimeInterface) {
            return CarbonImmutable::instance($value);
        }

        return is_string($value) && $value !== '' ? CarbonImmutable::parse($value) : null;
    }
}
