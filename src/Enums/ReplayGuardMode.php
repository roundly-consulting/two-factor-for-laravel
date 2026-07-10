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

        return self::tryFrom((string) $value)
            ?? throw InvalidTwoFactorConfigException::replayGuard((string) $value);
    }
}
