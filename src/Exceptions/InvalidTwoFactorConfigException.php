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

    public static function digits(int $value): self
    {
        return new self(sprintf(
            'Invalid two-factor "digits" (%d); expected an integer between 6 and 8.',
            $value,
        ));
    }

    public static function period(int $value): self
    {
        return new self(sprintf(
            'Invalid two-factor "period" (%d); expected an integer between 15 and 120 seconds.',
            $value,
        ));
    }

    public static function window(int $value): self
    {
        return new self(sprintf(
            'Invalid two-factor "window" (%d); expected an integer between 0 and 2 timesteps.',
            $value,
        ));
    }

    public static function secretLength(int $value): self
    {
        return new self(sprintf(
            'Invalid two-factor "secret_length" (%d); expected at least 16 base32 characters (80+ bits).',
            $value,
        ));
    }

    public static function attempts(string $key, int $value): self
    {
        return new self(sprintf(
            'Invalid two-factor "attempts.%s" (%d); expected an integer of at least 1.',
            $key,
            $value,
        ));
    }
}
