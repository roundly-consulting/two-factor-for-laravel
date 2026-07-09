<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Exceptions;

final class InvalidTwoFactorCodeException extends TwoFactorException
{
    public static function make(): self
    {
        return new self(__('The provided two-factor code is invalid.'));
    }
}
