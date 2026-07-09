<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Exceptions;

final class TwoFactorAlreadyEnabledException extends TwoFactorException
{
    public static function make(): self
    {
        return new self(__('Two-factor authentication is already enabled.'));
    }
}
