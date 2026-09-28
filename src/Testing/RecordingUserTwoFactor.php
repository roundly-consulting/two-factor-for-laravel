<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Testing;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;
use RoundlyConsulting\TwoFactor\DataTransferObjects\TwoFactorSetup;
use RoundlyConsulting\TwoFactor\DataTransferObjects\VerificationResult;
use RoundlyConsulting\TwoFactor\UserRecoveryCodes;
use RoundlyConsulting\TwoFactor\UserTwoFactor;
use SensitiveParameter;

/**
 * The user handle under `TwoFactor::fake()`: enrolment writes pass through to the
 * real actions (which run on the fake's canned primitives) and are recorded once
 * they succeed; `attempt()` returns the fake's programmed outcome.
 */
final readonly class RecordingUserTwoFactor extends UserTwoFactor
{
    public function __construct(
        private TwoFactorFake $fake,
        Container $container,
        TwoFactorAuthenticatable&Model $user,
    ) {
        parent::__construct($container, $user);
    }

    public function start(?string $label = null, ?string $issuer = null): TwoFactorSetup
    {
        $setup = parent::start($label, $issuer);

        $this->fake->recordStarted($this->user);

        return $setup;
    }

    public function confirm(#[SensitiveParameter] string $code): void
    {
        parent::confirm($code);

        $this->fake->recordConfirmed($this->user);
    }

    public function attempt(#[SensitiveParameter] string $code): VerificationResult
    {
        return $this->fake->recordAttempt($this->user, $code);
    }

    public function recoveryCodes(): UserRecoveryCodes
    {
        return new RecordingUserRecoveryCodes($this->fake, $this->container, $this->user);
    }

    public function disable(): void
    {
        parent::disable();

        $this->fake->recordDisabled($this->user);
    }
}
