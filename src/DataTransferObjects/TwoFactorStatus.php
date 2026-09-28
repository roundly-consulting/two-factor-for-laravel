<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\DataTransferObjects;

use Carbon\CarbonImmutable;

/**
 * A user's two-factor state in one read, from `TwoFactor::for($user)->status()`:
 * whether it is enabled, whether an enrolment is waiting for its first code, how
 * many single-use recovery codes remain, and when the current enrolment was
 * confirmed (null unless enabled).
 */
final readonly class TwoFactorStatus
{
    public function __construct(
        public bool $enabled,
        public bool $pending,
        public int $recoveryCodesRemaining,
        public ?CarbonImmutable $confirmedAt,
    ) {}
}
