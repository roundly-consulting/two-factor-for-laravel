<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Events;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

/**
 * Dispatched after StartEnrolment persists a fresh pending secret.
 */
final class TwoFactorEnrolmentStarted
{
    public function __construct(
        public readonly TwoFactorAuthenticatable&Model $user,
    ) {}
}
