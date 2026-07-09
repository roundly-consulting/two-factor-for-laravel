<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Enums;

use RoundlyConsulting\Enums\Helpers;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorConfigException;

enum RecoveryCodeStorage: string
{
    use Helpers;

    case Encrypted = 'encrypted';
    case Hashed = 'hashed';

    /**
     * The Eloquent cast applied to the recovery-codes column for this mode.
     *
     * Encrypted mode keeps plaintext codes encrypted at rest (so they can be
     * shown once and compared literally); hashed mode stores one-way hashes.
     */
    public function cast(): string
    {
        return match ($this) {
            self::Encrypted => 'encrypted:array',
            self::Hashed => 'array',
        };
    }

    /**
     * @throws InvalidTwoFactorConfigException
     */
    public static function fromConfig(string $value): self
    {
        return self::tryFrom($value)
            ?? throw InvalidTwoFactorConfigException::storage($value);
    }
}
