<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Tests\Fixtures;

use Illuminate\Foundation\Auth\User as Authenticatable;
use RoundlyConsulting\TwoFactor\Concerns\HasTwoFactorAuthentication;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

/**
 * A host user that overrides the provisioning label — proves twoFactorLabel()
 * is an overridable hook rather than a hardcoded email lookup.
 *
 * @property string|null $two_factor_secret
 * @property list<string>|null $two_factor_recovery_codes
 */
final class CustomLabelUser extends Authenticatable implements TwoFactorAuthenticatable
{
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

    public function twoFactorLabel(): string
    {
        return 'custom-label';
    }
}
