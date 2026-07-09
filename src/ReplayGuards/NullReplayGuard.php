<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\ReplayGuards;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\ReplayGuard;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

/**
 * Disables replay protection entirely — never records, never rejects.
 */
final class NullReplayGuard implements ReplayGuard
{
    public function latestTimestep(TwoFactorAuthenticatable&Model $user): ?int
    {
        return null;
    }

    public function record(TwoFactorAuthenticatable&Model $user, int $timestep): void
    {
        // Intentionally a no-op: replay protection is disabled.
    }

    public function reject(TwoFactorAuthenticatable&Model $user, int $timestep): bool
    {
        return false;
    }
}
