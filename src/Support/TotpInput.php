<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Support;

use SensitiveParameter;

/**
 * The form a typed TOTP code is verified in. People copy a code as "123 456" or
 * read it out as "123-456"; spaces and dashes are stripped only when exactly the
 * configured number of digits remains. Every such spelling maps onto one code,
 * so this widens nothing an attacker can use, and anything else (a recovery code,
 * a malformed code) passes through as typed.
 *
 * @internal used by the confirm and attempt actions and the fake
 */
final class TotpInput
{
    public static function normalize(#[SensitiveParameter] string $code): string
    {
        $compact = str_replace([' ', '-'], '', $code);

        return strlen($compact) === ConfigGuard::digits() && ctype_digit($compact) ? $compact : $code;
    }
}
