<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Enums;

use RoundlyConsulting\Enums\Helpers;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorConfigException;

enum ReplayGuardMode: string
{
    use Helpers;

    case Column = 'column';
    case Cache = 'cache';
    case None = 'none';

    /**
     * Resolve the configured replay-guard mode. A null config value (or the
     * literal 'none') disables replay protection via the NullReplayGuard.
     *
     * @throws InvalidTwoFactorConfigException
     */
    public static function fromConfig(mixed $value): self
    {
        if ($value === null) {
            return self::None;
        }

        if ($value instanceof self) {
            return $value;
        }

        // Strings only: a `false` or `0` is not how replay protection is switched off.
        return (is_string($value) ? self::tryFrom($value) : null)
            ?? throw InvalidTwoFactorConfigException::replayGuard(is_scalar($value) ? var_export($value, true) : get_debug_type($value));
    }
}
