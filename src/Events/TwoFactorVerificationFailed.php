<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Events;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

/**
 * Dispatched when an enrolled user fails a two-factor challenge (no TOTP match
 * and no recovery-code match). Not dispatched on a replay rejection (that emits
 * TwoFactorReplayDetected) or when the user has no secret. No code is carried.
 */
final class TwoFactorVerificationFailed
{
    public function __construct(
        public readonly TwoFactorAuthenticatable&Model $user,
    ) {}
}
