<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\ReplayGuards;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\ReplayGuard;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

/**
 * Disables replay protection entirely — every claim succeeds, nothing is tracked.
 */
final class NullReplayGuard implements ReplayGuard
{
    public function latestTimestep(TwoFactorAuthenticatable&Model $user): ?int
    {
        return null;
    }

    public function claim(TwoFactorAuthenticatable&Model $user, int $timestep): bool
    {
        // Replay protection is disabled: always allow the timestep.
        return true;
    }
}
