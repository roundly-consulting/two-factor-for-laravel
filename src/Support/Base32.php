<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Support;

use RoundlyConsulting\TwoFactor\Exceptions\InvalidBase32Exception;

/**
 * RFC 4648 base32 codec over the alphabet A–Z2–7, without padding on encode.
 *
 * The decoder is intentionally lenient (case-insensitive, tolerates `=` padding
 * and whitespace) but strict about the alphabet, so it decodes secrets produced
 * by google2fa to byte-identical key material.
 */
final class Base32
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function encode(string $bytes): string
    {
        if ($bytes === '') {
            return '';
        }

        $binary = '';

        foreach (str_split($bytes) as $byte) {
            $binary .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
        }

        $output = '';

        foreach (str_split($binary, 5) as $chunk) {
            $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            $output .= self::ALPHABET[(int) bindec($chunk)];
        }

        return $output;
    }

    /**
     * @throws InvalidBase32Exception when a character outside the alphabet remains.
     */
    public static function decode(string $base32): string
    {
        $normalized = strtoupper($base32);
        $normalized = (string) preg_replace('/[\s=]+/', '', $normalized);

        if ($normalized === '') {
            return '';
        }

        $binary = '';

        foreach (str_split($normalized) as $character) {
            $position = strpos(self::ALPHABET, $character);

            if ($position === false) {
                throw InvalidBase32Exception::character($character);
            }

            $binary .= str_pad(decbin($position), 5, '0', STR_PAD_LEFT);
        }

        $bytes = '';

        foreach (str_split($binary, 8) as $chunk) {
            if (strlen($chunk) === 8) {
                $bytes .= chr((int) bindec($chunk));
            }
        }

        return $bytes;
    }
}
