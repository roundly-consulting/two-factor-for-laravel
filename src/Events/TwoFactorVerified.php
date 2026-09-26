<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Events;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;
use RoundlyConsulting\TwoFactor\Enums\TwoFactorMethod;

/**
 * Dispatched when a user passes a two-factor challenge via attempt()/verifyFor()
 * — carries which factor (TOTP or a recovery code) passed it, so hosts can audit
 * challenges and meter success rates. No secret or code is carried.
 */
final class TwoFactorVerified
{
    public function __construct(
        public readonly TwoFactorAuthenticatable&Model $user,
        public readonly TwoFactorMethod $method,
    ) {}
}
