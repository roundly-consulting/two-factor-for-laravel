<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Exceptions;

/**
 * Thrown by verifyFor() when the built-in brute-force limiter has locked a user's
 * two-factor challenge. Hosts can catch this to render a "try again later" state.
 */
final class TwoFactorRateLimitedException extends TwoFactorException
{
    private function __construct(
        public readonly int $secondsUntilAvailable,
        string $message,
    ) {
        parent::__construct($message);
    }

    public static function make(int $secondsUntilAvailable): self
    {
        return new self(
            $secondsUntilAvailable,
            sprintf('Too many two-factor attempts; retry in %d second(s).', $secondsUntilAvailable),
        );
    }
}
