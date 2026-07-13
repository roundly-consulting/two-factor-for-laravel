<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Support;

use Illuminate\Support\Facades\Hash;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\TwoFactor\Enums\RecoveryCodeStorage;
use SensitiveParameter;

/**
 * Generates, formats and single-use-consumes recovery codes.
 *
 * In encrypted mode the stored value is the plaintext code (kept encrypted at
 * rest by the model cast) and matched in constant time. In hashed mode the
 * stored value is a one-way hash matched with Hash::check.
 */
final readonly class RecoveryCodeManager
{
    private const ALPHABET = 'ABCDEFGHIJKLMNPQRSTUVWXYZ0123456789';

    private const SEGMENT = 5;

    public function __construct(
        private RecoveryCodeStorage $storage = RecoveryCodeStorage::Encrypted,
    ) {}

    /**
     * @return list<string> plaintext codes to show the user once
     */
    public function generate(int $count): array
    {
        $codes = [];

        for ($i = 0; $i < $count; $i++) {
            $codes[] = $this->segment().'-'.$this->segment();
        }

        return $codes;
    }

    /**
     * Prepare a plaintext code list for storage under the active mode.
     *
     * @param  list<string>  $codes
     * @return list<string>
     */
    public function forStorage(array $codes): array
    {
        if ($this->storage === RecoveryCodeStorage::Hashed) {
            return array_map(static fn (string $code): string => Hash::make($code), $codes);
        }

        return $codes;
    }

    /**
     * Consume a candidate code, returning the reduced stored list with exactly
     * the matched entry removed, or null when nothing matched (list untouched).
     *
     * @param  list<string>  $stored
     * @return list<string>|null
     */
    public function consume(array $stored, #[SensitiveParameter] string $candidate): ?array
    {
        foreach ($stored as $index => $storedCode) {
            if ($this->matches($storedCode, $candidate)) {
                unset($stored[$index]);

                return array_values($stored);
            }
        }

        return null;
    }

    private function matches(string $storedCode, #[SensitiveParameter] string $candidate): bool
    {
        if ($this->storage === RecoveryCodeStorage::Hashed) {
            return Hash::check($candidate, $storedCode);
        }

        return ConstantTime::equals($storedCode, $candidate);
    }

    private function segment(): string
    {
        $max = strlen(self::ALPHABET) - 1;
        $segment = '';

        for ($i = 0; $i < self::SEGMENT; $i++) {
            $segment .= self::ALPHABET[random_int(0, $max)];
        }

        return $segment;
    }
}
