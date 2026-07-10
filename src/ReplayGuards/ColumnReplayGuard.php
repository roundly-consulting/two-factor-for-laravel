<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\ReplayGuards;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder;
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

    public function claim(TwoFactorAuthenticatable&Model $user, int $timestep): bool
    {
        $column = $this->column();

        // A single conditional UPDATE is the whole claim: the row is locked for
        // the write, so of two concurrent submissions of the same code exactly
        // one affects a row. Scoped to the timestep column via the base builder
        // so no unrelated dirty attribute or updated_at is flushed (finding 11).
        $affected = $user->newQuery()
            ->toBase()
            ->where($user->getKeyName(), $user->getKey())
            ->where(function (Builder $query) use ($column, $timestep): void {
                $query->whereNull($column)->orWhere($column, '<', $timestep);
            })
            ->update([$column => $timestep]);

        if ($affected > 0) {
            // Keep the in-memory model consistent without marking it dirty.
            $user->setAttribute($column, $timestep);
            $user->syncOriginalAttribute($column);

            return true;
        }

        return false;
    }

    private function column(): string
    {
        return (string) config('two-factor.columns.last_used_timestep');
    }
}
