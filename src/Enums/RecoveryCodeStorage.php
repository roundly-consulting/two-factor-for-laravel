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
     * Resolve a configured storage mode: a case, or its exact value. Anything else
     * — a typo, a non-string — throws rather than changing how codes are kept.
     *
     * @throws InvalidTwoFactorConfigException
     */
    public static function fromConfig(mixed $value): self
    {
        if ($value instanceof self) {
            return $value;
        }

        return (is_string($value) ? self::tryFrom($value) : null)
            ?? throw InvalidTwoFactorConfigException::storage(is_scalar($value) ? (string) $value : get_debug_type($value));
    }
}
