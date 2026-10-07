<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Exceptions;

use RoundlyConsulting\Crypto\Otp\InvalidOtpParameterException;

/**
 * Thrown when a two-factor secret is valid base32 but no usable key: empty,
 * shorter than the OTP primitive's minimum, or all zero bytes.
 */
final class InvalidTwoFactorSecretException extends TwoFactorException
{
    /**
     * Re-classify the OTP primitive's secret failure as this package's exception,
     * so crypto's own exception never escapes the boundary.
     */
    public static function fromOtp(InvalidOtpParameterException $exception): self
    {
        return new self(
            'The two-factor secret is not a usable key. '.$exception->getMessage(),
            previous: $exception,
        );
    }
}
