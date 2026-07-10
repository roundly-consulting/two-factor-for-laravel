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
    /**
     * The latest recorded timestep for introspection (or null when none yet).
     */
    public function latestTimestep(TwoFactorAuthenticatable&Model $user): ?int;

    /**
     * Atomically claim $timestep for the user in a single check-and-set. Returns
     * true when the timestep was newly claimed (the code may be accepted) and
     * false when it was already used — a replay — so two concurrent submissions
     * of the same code cannot both succeed.
     */
    public function claim(TwoFactorAuthenticatable&Model $user, int $timestep): bool;
}
