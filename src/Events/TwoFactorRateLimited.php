<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Events;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

/**
 * Dispatched when the built-in brute-force limiter locks a user's two-factor
 * challenge — hosts can alert, log, or notify on repeated failed attempts.
 */
final class TwoFactorRateLimited
{
    public function __construct(
        public readonly TwoFactorAuthenticatable&Model $user,
        public readonly int $secondsUntilAvailable,
    ) {}
}
