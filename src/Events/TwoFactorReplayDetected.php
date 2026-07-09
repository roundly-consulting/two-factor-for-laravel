<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Events;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

/**
 * Dispatched when a code is rejected because its timestep was already used —
 * hosts can alert or rate-limit on this signal.
 */
final class TwoFactorReplayDetected
{
    public function __construct(
        public readonly TwoFactorAuthenticatable&Model $user,
        public readonly int $timestep,
    ) {}
}
