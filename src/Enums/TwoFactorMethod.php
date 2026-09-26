<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * Which factor satisfied a two-factor verification: a time-based authenticator
 * code or a single-use recovery code. Hosts map it to an `amr` claim, an audit
 * row, or a "recovery code used" notification.
 */
enum TwoFactorMethod: string
{
    use Helpers;

    case Totp = 'totp';
    case RecoveryCode = 'recovery_code';
}
