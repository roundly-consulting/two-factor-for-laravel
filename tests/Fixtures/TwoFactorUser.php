<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Tests\Fixtures;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use RoundlyConsulting\TwoFactor\Concerns\HasTwoFactorAuthentication;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

/**
 * Testbench stand-in for a host user model. The package owns no table, so this
 * fixture models the host `users` row the trait operates on.
 *
 * @property string|null $two_factor_secret
 * @property list<string>|null $two_factor_recovery_codes
 * @property CarbonInterface|null $two_factor_confirmed_at
 * @property int|null $two_factor_last_used_timestep
 */
class TwoFactorUser extends Authenticatable implements TwoFactorAuthenticatable
{
    /** @use HasFactory<TwoFactorUserFactory> */
    use HasFactory;

    use HasTwoFactorAuthentication;

    protected $table = 'users';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [...$this->twoFactorCasts()];
    }

    protected static function newFactory(): TwoFactorUserFactory
    {
        return TwoFactorUserFactory::new();
    }
}
