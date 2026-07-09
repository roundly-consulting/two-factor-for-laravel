<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Contracts;

/**
 * Implemented by the host user model (via HasTwoFactorAuthentication) so the
 * package can read enrolment state without knowing the model's shape.
 */
interface TwoFactorAuthenticatable
{
    public function hasTwoFactorEnabled(): bool;

    public function hasPendingTwoFactor(): bool;

    public function twoFactorSecret(): ?string;

    /**
     * @return list<string>
     */
    public function twoFactorRecoveryCodes(): array;
}
