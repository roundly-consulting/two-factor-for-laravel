<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Exceptions;

final class TwoFactorNotPendingException extends TwoFactorException
{
    public static function make(): self
    {
        return new self(__('There is no pending two-factor enrolment to confirm.'));
    }
}
