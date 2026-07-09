<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Concerns;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Enums\RecoveryCodeStorage;

/**
 * Gives a host user model the two-factor state helpers required by
 * TwoFactorAuthenticatable. Spread twoFactorCasts() into the model's casts():
 *
 * ```php
 * protected function casts(): array
 * {
 *     return [...$this->twoFactorCasts()];
 * }
 * ```
 *
 * Column names are always read through config('two-factor.columns') so a host
 * with a remapped schema stays in control.
 *
 * @phpstan-require-extends Model
 */
trait HasTwoFactorAuthentication
{
    /**
     * @return array<string, string>
     */
    public function twoFactorCasts(): array
    {
        $columns = $this->twoFactorColumnMap();

        return [
            $columns['secret'] => 'encrypted',
            $columns['recovery_codes'] => RecoveryCodeStorage::fromConfig(
                (string) config('two-factor.recovery_codes.storage'),
            )->cast(),
            $columns['confirmed_at'] => 'datetime',
        ];
    }

    public function hasTwoFactorEnabled(): bool
    {
        return $this->twoFactorSecret() !== null
            && $this->getAttribute($this->twoFactorColumnMap()['confirmed_at']) !== null;
    }

    public function hasPendingTwoFactor(): bool
    {
        return $this->twoFactorSecret() !== null
            && $this->getAttribute($this->twoFactorColumnMap()['confirmed_at']) === null;
    }

    public function twoFactorSecret(): ?string
    {
        $secret = $this->getAttribute($this->twoFactorColumnMap()['secret']);

        return $secret === null ? null : (string) $secret;
    }

    /**
     * @return list<string>
     */
    public function twoFactorRecoveryCodes(): array
    {
        $codes = $this->getAttribute($this->twoFactorColumnMap()['recovery_codes']);

        if (! is_array($codes)) {
            return [];
        }

        return array_values(array_map(strval(...), $codes));
    }

    /**
     * @return array{secret: string, recovery_codes: string, confirmed_at: string, last_used_timestep: string}
     */
    protected function twoFactorColumnMap(): array
    {
        /** @var array{secret: string, recovery_codes: string, confirmed_at: string, last_used_timestep: string} $columns */
        $columns = config('two-factor.columns');

        return $columns;
    }
}
