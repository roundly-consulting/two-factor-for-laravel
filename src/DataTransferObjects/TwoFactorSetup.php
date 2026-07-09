<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\DataTransferObjects;

use SensitiveParameter;

/**
 * The one-time enrolment payload: the base32 secret, the otpauth:// URI the
 * frontend renders as a QR, and the plaintext recovery codes to show once.
 */
final readonly class TwoFactorSetup
{
    /**
     * @param  list<string>  $recoveryCodes
     */
    public function __construct(
        #[SensitiveParameter] public string $secret,
        public string $provisioningUri,
        public array $recoveryCodes,
    ) {}
}
