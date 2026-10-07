<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Support;

use Illuminate\Support\Facades\Hash;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\Crypto\Random\Token;
use RoundlyConsulting\TwoFactor\Enums\RecoveryCodeStorage;
use SensitiveParameter;

/**
 * Generates, formats and single-use-consumes recovery codes.
 *
 * In encrypted mode the stored value is the plaintext code (kept encrypted at
 * rest by the model cast) and matched in constant time. In hashed mode the
 * stored value is a one-way hash matched with Hash::check. Either way the typed
 * candidate is normalized first (see normalize()), so case, stray whitespace and
 * the dash never cost a user an attempt.
 *
 * @internal a building block of the enrolment and attempt actions
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
        $matched = $this->match($stored, $candidate);

        return $matched === null ? null : self::without($stored, $matched);
    }

    /**
     * The stored entry the candidate matches, or null. In hashed mode this is one
     * Hash::check per stored entry, so run it outside any row lock and re-confirm
     * the entry under the lock with without().
     *
     * @param  list<string>  $stored
     */
    public function match(array $stored, #[SensitiveParameter] string $candidate): ?string
    {
        $candidate = self::normalize($candidate);

        foreach ($stored as $storedCode) {
            if ($this->matches($storedCode, $candidate)) {
                return $storedCode;
            }
        }

        return null;
    }

    /**
     * The stored list with exactly one occurrence of an entry match() returned
     * removed — compared by string identity, no hashing — or null when the entry
     * is no longer stored (spent or replaced since it was matched).
     *
     * @param  list<string>  $stored
     * @return list<string>|null
     */
    public static function without(array $stored, #[SensitiveParameter] string $entry): ?array
    {
        $index = array_search($entry, $stored, true);

        if ($index === false) {
            return null;
        }

        unset($stored[$index]);

        return array_values($stored);
    }

    /**
     * @param  string  $candidate  already normalized
     */
    private function matches(string $storedCode, #[SensitiveParameter] string $candidate): bool
    {
        // Hashed codes were hashed from their canonical form at generation.
        if ($this->storage === RecoveryCodeStorage::Hashed) {
            return Hash::check($candidate, $storedCode);
        }

        // Plaintext is normalized too, so an imported code of this shape that was
        // stored in lowercase still matches.
        return ConstantTime::equals(self::normalize($storedCode), $candidate);
    }

    /**
     * The form a code is compared in. A code of this package's own shape — ten
     * alphanumerics, optionally split by a dash and/or spaces — becomes the
     * canonical `XXXXX-XXXXX`: upper-cased, with a typed letter O (never issued)
     * read as the zero it was mistaken for. Anything else (an imported code of
     * another shape) is only trimmed and must otherwise match exactly.
     *
     * Every spelling maps onto one issued code, so this widens nothing an
     * attacker can use; each code still matches once.
     */
    private static function normalize(#[SensitiveParameter] string $code): string
    {
        $trimmed = trim($code);
        $compact = strtoupper(str_replace(['-', ' '], '', $trimmed));

        if (preg_match('/^[A-Z0-9]{'.(self::SEGMENT * 2).'}$/', $compact) !== 1) {
            return $trimmed;
        }

        $compact = strtr($compact, 'O', '0');

        return substr($compact, 0, self::SEGMENT).'-'.substr($compact, self::SEGMENT);
    }

    /**
     * The uniform CSPRNG draw lives in crypto-for-laravel; this only owns the alphabet
     * (O excluded so codes stay unambiguous on paper) and the segment length.
     */
    private function segment(): string
    {
        return Token::fromAlphabet(self::ALPHABET, self::SEGMENT);
    }
}
