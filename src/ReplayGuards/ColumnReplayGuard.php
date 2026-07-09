<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\ReplayGuards;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\ReplayGuard;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

/**
 * Persists the last-used timestep to a column on the user row.
 */
final class ColumnReplayGuard implements ReplayGuard
{
    public function latestTimestep(TwoFactorAuthenticatable&Model $user): ?int
    {
        $value = $user->getAttribute($this->column());

        return $value === null ? null : (int) $value;
    }

    public function record(TwoFactorAuthenticatable&Model $user, int $timestep): void
    {
        $user->setAttribute($this->column(), $timestep);
        $user->save();
    }

    public function reject(TwoFactorAuthenticatable&Model $user, int $timestep): bool
    {
        $latest = $this->latestTimestep($user);

        return $latest !== null && $timestep <= $latest;
    }

    private function column(): string
    {
        return (string) config('two-factor.columns.last_used_timestep');
    }
}
