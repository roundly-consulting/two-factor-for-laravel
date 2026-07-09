<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Events;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

/**
 * Dispatched after DisableTwoFactor clears all two-factor state.
 */
final class TwoFactorDisabled
{
    public function __construct(
        public readonly TwoFactorAuthenticatable&Model $user,
    ) {}
}
