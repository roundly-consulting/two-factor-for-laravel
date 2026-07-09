<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Events;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

/**
 * Dispatched after RegenerateRecoveryCodes replaces the code set.
 */
final class RecoveryCodesRegenerated
{
    public function __construct(
        public readonly TwoFactorAuthenticatable&Model $user,
    ) {}
}
