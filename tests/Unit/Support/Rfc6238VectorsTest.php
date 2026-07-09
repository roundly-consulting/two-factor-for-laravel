<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\Enums\HashAlgorithm;
use RoundlyConsulting\TwoFactor\Support\Base32;
use RoundlyConsulting\TwoFactor\Support\Totp;

/**
 * RFC 6238 Appendix B seeds (repeated ASCII of the right length per algorithm).
 */
function rfc6238Seed(HashAlgorithm $algorithm): string
{
    return match ($algorithm) {
        HashAlgorithm::Sha1 => str_repeat('1234567890', 2),          // 20 bytes
        HashAlgorithm::Sha256 => str_repeat('1234567890', 3).'12',   // 32 bytes
        HashAlgorithm::Sha512 => str_repeat('1234567890', 6).'1234', // 64 bytes
    };
}

dataset('rfc6238', [
    [HashAlgorithm::Sha1, 59, '94287082'],
    [HashAlgorithm::Sha256, 59, '46119246'],
    [HashAlgorithm::Sha512, 59, '90693936'],
    [HashAlgorithm::Sha1, 1111111109, '07081804'],
    [HashAlgorithm::Sha256, 1111111109, '68084774'],
    [HashAlgorithm::Sha512, 1111111109, '25091201'],
    [HashAlgorithm::Sha1, 1111111111, '14050471'],
    [HashAlgorithm::Sha256, 1111111111, '67062674'],
    [HashAlgorithm::Sha512, 1111111111, '99943326'],
    [HashAlgorithm::Sha1, 1234567890, '89005924'],
    [HashAlgorithm::Sha256, 1234567890, '91819424'],
    [HashAlgorithm::Sha512, 1234567890, '93441116'],
    [HashAlgorithm::Sha1, 2000000000, '69279037'],
    [HashAlgorithm::Sha256, 2000000000, '90698825'],
    [HashAlgorithm::Sha512, 2000000000, '38618901'],
    [HashAlgorithm::Sha1, 20000000000, '65353130'],
    [HashAlgorithm::Sha256, 20000000000, '77737706'],
    [HashAlgorithm::Sha512, 20000000000, '47863826'],
]);

it('matches every RFC 6238 Appendix B TOTP vector', function (HashAlgorithm $algorithm, int $timestamp, string $expected): void {
    $totp = new Totp($algorithm, 8, 30);
    $secret = Base32::encode(rfc6238Seed($algorithm));

    expect($totp->codeAt($secret, $timestamp))->toBe($expected);
})->with('rfc6238');
