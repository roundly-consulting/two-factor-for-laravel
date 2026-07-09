<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Contracts;

use Illuminate\Database\Eloquent\Model;

/**
 * Tracks the last successfully-used TOTP timestep for a user so a code cannot be
 * replayed within its drift window.
 */
interface ReplayGuard
{
    public function latestTimestep(TwoFactorAuthenticatable&Model $user): ?int;

    public function record(TwoFactorAuthenticatable&Model $user, int $timestep): void;

    /**
     * Whether a code at $timestep must be rejected as a replay (timestep already
     * used, i.e. <= the latest recorded one).
     */
    public function reject(TwoFactorAuthenticatable&Model $user, int $timestep): bool;
}
