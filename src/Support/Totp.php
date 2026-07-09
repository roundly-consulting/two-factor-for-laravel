<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Support;

use RoundlyConsulting\TwoFactor\Enums\HashAlgorithm;
use SensitiveParameter;

/**
 * RFC 4226 (HOTP) / RFC 6238 (TOTP) generator and verifier.
 *
 * All code comparison goes through hash_equals so verification runs in constant
 * time and never leaks which timestep matched beyond the returned value.
 */
final readonly class Totp
{
    public function __construct(
        private HashAlgorithm $algorithm = HashAlgorithm::Sha1,
        private int $digits = 6,
        private int $period = 30,
    ) {}

    /**
     * The RFC 4226 HOTP value for a counter and base32 secret.
     */
    public function hotp(#[SensitiveParameter] string $secret, int $counter): string
    {
        $key = Base32::decode($secret);
        $hash = hash_hmac($this->algorithm->hashHmacAlgo(), pack('J', $counter), $key, true);

        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;

        $binary = ((ord($hash[$offset]) & 0x7F) << 24)
            | ((ord($hash[$offset + 1]) & 0xFF) << 16)
            | ((ord($hash[$offset + 2]) & 0xFF) << 8)
            | (ord($hash[$offset + 3]) & 0xFF);

        $otp = $binary % (10 ** $this->digits);

        return str_pad((string) $otp, $this->digits, '0', STR_PAD_LEFT);
    }

    /**
     * The timestep index (counter) for a given unix timestamp.
     */
    public function timestepAt(int $timestamp): int
    {
        return intdiv($timestamp, $this->period);
    }

    /**
     * The TOTP value for an explicit timestep.
     */
    public function at(#[SensitiveParameter] string $secret, int $timestep): string
    {
        return $this->hotp($secret, $timestep);
    }

    /**
     * The TOTP value at a unix timestamp (defaults to now).
     */
    public function codeAt(#[SensitiveParameter] string $secret, ?int $timestamp = null): string
    {
        $timestamp ??= now()->getTimestamp();

        return $this->at($secret, $this->timestepAt($timestamp));
    }

    /**
     * Verify a code against the drift window, returning the matched timestep or
     * false. Malformed codes are rejected before any HMAC work is done.
     *
     * @return int|false the matched timestep index
     */
    public function verify(
        #[SensitiveParameter] string $secret,
        #[SensitiveParameter] string $code,
        int $window = 1,
        ?int $timestamp = null,
    ): int|false {
        if (! $this->isWellFormed($code)) {
            return false;
        }

        $timestamp ??= now()->getTimestamp();
        $current = $this->timestepAt($timestamp);

        $matched = false;

        // Check every step in the window without early return so a match late in
        // the window costs the same as one early — the loop leaks no timing.
        for ($step = $current - $window; $step <= $current + $window; $step++) {
            if (hash_equals($this->at($secret, $step), $code)) {
                $matched = $step;
            }
        }

        return $matched;
    }

    private function isWellFormed(string $code): bool
    {
        return strlen($code) === $this->digits && ctype_digit($code);
    }
}
