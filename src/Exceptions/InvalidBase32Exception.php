<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Exceptions;

use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;

/**
 * Thrown when a two-factor secret is not valid base32 and cannot be decoded to
 * key material.
 */
final class InvalidBase32Exception extends TwoFactorException
{
    /**
     * Re-classify the codec's decoding failure as this package's exception, so a
     * malformed secret keeps surfacing as InvalidBase32Exception to callers
     * regardless of which codec decoded it.
     */
    public static function fromCodec(InvalidEncodingException $exception): self
    {
        return new self(
            'The two-factor secret is not valid base32. '.$exception->getMessage(),
            previous: $exception,
        );
    }
}
