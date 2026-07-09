<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Enums;

use RoundlyConsulting\Enums\Helpers;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorConfigException;

enum HashAlgorithm: string
{
    use Helpers;

    case Sha1 = 'sha1';
    case Sha256 = 'sha256';
    case Sha512 = 'sha512';

    /**
     * The algorithm name understood by hash_hmac().
     */
    public function hashHmacAlgo(): string
    {
        return $this->value;
    }

    /**
     * Resolve a configured algorithm string into an enum, failing loudly on an
     * unsupported value rather than silently downgrading the hash.
     *
     * @throws InvalidTwoFactorConfigException
     */
    public static function fromConfig(string $value): self
    {
        return self::tryFrom($value)
            ?? throw InvalidTwoFactorConfigException::algorithm($value);
    }
}
