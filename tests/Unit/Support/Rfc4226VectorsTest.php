<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\Enums\HashAlgorithm;
use RoundlyConsulting\TwoFactor\Support\Base32;
use RoundlyConsulting\TwoFactor\Support\Totp;

dataset('rfc4226', [
    [0, '755224'],
    [1, '287082'],
    [2, '359152'],
    [3, '969429'],
    [4, '338314'],
    [5, '254676'],
    [6, '287922'],
    [7, '162583'],
    [8, '399871'],
    [9, '520489'],
]);

it('matches every RFC 4226 Appendix D HOTP vector', function (int $counter, string $expected): void {
    $totp = new Totp(HashAlgorithm::Sha1, 6, 30);
    $secret = Base32::encode('12345678901234567890');

    expect($totp->hotp($secret, $counter))->toBe($expected);
})->with('rfc4226');
