<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Exceptions;

final class InvalidBase32Exception extends TwoFactorException
{
    public static function character(string $character): self
    {
        return new self(sprintf('Invalid base32 character "%s".', $character));
    }
}
