<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Exceptions;

final class TwoFactorNotPendingException extends TwoFactorException
{
    public static function make(): self
    {
        return new self(__('There is no pending two-factor enrolment to confirm.'));
    }

    /**
     * Confirming an enrolment that is already enabled: nothing is pending.
     */
    public static function alreadyEnabled(): self
    {
        return new self(__('Two-factor authentication is already enabled; there is no pending enrolment to confirm.'));
    }
}
