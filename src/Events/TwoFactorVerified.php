<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Events;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

/**
 * Dispatched when a user passes a two-factor challenge via verifyFor() —
 * carries whether a recovery code (rather than a TOTP code) was used, so hosts
 * can audit challenges and meter success rates. No secret or code is carried.
 */
final class TwoFactorVerified
{
    public function __construct(
        public readonly TwoFactorAuthenticatable&Model $user,
        public readonly bool $viaRecoveryCode,
    ) {}
}
