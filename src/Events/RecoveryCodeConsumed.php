<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Events;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

/**
 * Dispatched when verifyFor() burns a single-use recovery code as a fallback.
 */
final class RecoveryCodeConsumed
{
    public function __construct(
        public readonly TwoFactorAuthenticatable&Model $user,
    ) {}
}
