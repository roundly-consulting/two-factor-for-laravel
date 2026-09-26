<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\DataTransferObjects;

use RoundlyConsulting\TwoFactor\Enums\TwoFactorMethod;

/**
 * The outcome of a single two-factor attempt: whether it passed, which factor
 * passed it, and how many single-use recovery codes the user has left after
 * it. `replayed` flags a code that was valid for its timestep but whose
 * timestep had already been claimed — a failure, reported apart so a host can
 * tell "wrong code" from "code reused".
 */
final readonly class VerificationResult
{
    public function __construct(
        public bool $verified,
        public ?TwoFactorMethod $method,
        public int $remainingRecoveryCodes,
        public bool $replayed = false,
    ) {}

    public static function failed(int $remaining, bool $replayed = false): self
    {
        return new self(verified: false, method: null, remainingRecoveryCodes: $remaining, replayed: $replayed);
    }

    public static function via(TwoFactorMethod $method, int $remaining): self
    {
        return new self(verified: true, method: $method, remainingRecoveryCodes: $remaining);
    }
}
