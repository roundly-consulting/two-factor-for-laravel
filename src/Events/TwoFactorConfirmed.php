<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Events;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

/**
 * Dispatched when ConfirmEnrolment transitions the user to enabled.
 */
final class TwoFactorConfirmed
{
    public function __construct(
        public readonly TwoFactorAuthenticatable&Model $user,
    ) {}
}
