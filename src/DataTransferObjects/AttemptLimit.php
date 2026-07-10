<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\DataTransferObjects;

/**
 * The resolved brute-force limiter budget for verifyFor(): at most $max failed
 * attempts within a rolling $decay-second window before a challenge is locked.
 */
final readonly class AttemptLimit
{
    public function __construct(
        public int $max,
        public int $decay,
    ) {}
}
