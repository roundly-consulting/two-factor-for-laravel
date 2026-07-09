<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use RoundlyConsulting\TwoFactor\Enums\HashAlgorithm;
use RoundlyConsulting\TwoFactor\Support\Base32;
use RoundlyConsulting\TwoFactor\Support\Totp;

function secretFor(string $ascii): string
{
    return Base32::encode($ascii);
}

it('left-pads short codes to the configured digit count', function (): void {
    $totp = new Totp(HashAlgorithm::Sha1, 6, 30);

    expect($totp->hotp(secretFor('12345678901234567890'), 0))->toBe('755224')->toHaveLength(6);
});

it('computes the code at a timestep and at a timestamp identically', function (): void {
    $totp = new Totp(HashAlgorithm::Sha1, 6, 30);
    $secret = secretFor('12345678901234567890');

    expect($totp->at($secret, 2))->toBe($totp->codeAt($secret, 75)); // 75 / 30 = timestep 2
});

it('accepts the exact step with window 0', function (): void {
    $totp = new Totp(HashAlgorithm::Sha1, 6, 30);
    $secret = secretFor('12345678901234567890');
    $code = $totp->codeAt($secret, 90);

    expect($totp->verify($secret, $code, 0, 90))->toBe(3)
        ->and($totp->verify($secret, $code, 0, 60))->toBeFalse();
});

it('accepts drift of plus or minus one step but not two', function (): void {
    $totp = new Totp(HashAlgorithm::Sha1, 6, 30);
    $secret = secretFor('12345678901234567890');
    $previous = $totp->codeAt($secret, 60); // timestep 2, verifying at timestep 3

    expect($totp->verify($secret, $previous, 1, 90))->toBe(2)
        ->and($totp->verify($secret, $previous, 1, 150))->toBeFalse(); // two steps away
});

it('rejects malformed codes before any hashing', function (): void {
    $totp = new Totp(HashAlgorithm::Sha1, 6, 30);
    $secret = secretFor('12345678901234567890');

    expect($totp->verify($secret, '12ab56', 1, 90))->toBeFalse()
        ->and($totp->verify($secret, '1234', 1, 90))->toBeFalse()
        ->and($totp->verify($secret, '1234567', 1, 90))->toBeFalse();
});

it('produces different codes per algorithm for the same secret and time', function (): void {
    $secret = secretFor('12345678901234567890123456789012');

    $sha1 = (new Totp(HashAlgorithm::Sha1, 6, 30))->codeAt($secret, 1111111111);
    $sha256 = (new Totp(HashAlgorithm::Sha256, 6, 30))->codeAt($secret, 1111111111);

    expect($sha1)->not->toBe($sha256);
});

it('defaults the timestamp to the current time', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(90));

    $totp = new Totp(HashAlgorithm::Sha1, 6, 30);
    $secret = secretFor('12345678901234567890');

    expect($totp->codeAt($secret))->toBe($totp->codeAt($secret, 90))
        ->and($totp->verify($secret, $totp->codeAt($secret)))->toBe(3);

    Carbon::setTestNow();
});
