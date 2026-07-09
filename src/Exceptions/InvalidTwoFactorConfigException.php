<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Exceptions;

final class InvalidTwoFactorConfigException extends TwoFactorException
{
    public static function algorithm(string $value): self
    {
        return new self(sprintf(
            'Unsupported two-factor hash algorithm "%s"; expected sha1, sha256 or sha512.',
            $value,
        ));
    }

    public static function storage(string $value): self
    {
        return new self(sprintf(
            'Unsupported recovery-code storage "%s"; expected encrypted or hashed.',
            $value,
        ));
    }

    public static function replayGuard(string $value): self
    {
        return new self(sprintf(
            'Unsupported replay guard "%s"; expected column, cache or null.',
            $value,
        ));
    }
}
