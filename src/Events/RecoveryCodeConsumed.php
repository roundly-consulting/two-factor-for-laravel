<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Events;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

/**
 * Dispatched when attempt()/verifyFor() burns a single-use recovery code as a
 * fallback. `$remaining` is the count left after this one was spent — the
 * number a "recovery code used, N left" notification shows.
 */
final class RecoveryCodeConsumed
{
    public function __construct(
        public readonly TwoFactorAuthenticatable&Model $user,
        public readonly int $remaining,
    ) {}
}
