<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\Enums\HashAlgorithm;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorConfigException;

it('maps each case to its hash_hmac algorithm name', function (): void {
    expect(HashAlgorithm::Sha1->hashHmacAlgo())->toBe('sha1')
        ->and(HashAlgorithm::Sha256->hashHmacAlgo())->toBe('sha256')
        ->and(HashAlgorithm::Sha512->hashHmacAlgo())->toBe('sha512');
});

it('resolves a valid config string', function (): void {
    expect(HashAlgorithm::fromConfig('sha256'))->toBe(HashAlgorithm::Sha256);
});

it('throws on an unsupported algorithm', function (): void {
    HashAlgorithm::fromConfig('md5');
})->throws(InvalidTwoFactorConfigException::class);

it('exposes the enums-for-laravel helpers surface', function (): void {
    expect(HashAlgorithm::values()->all())->toBe(['sha1', 'sha256', 'sha512'])
        ->and(HashAlgorithm::count())->toBe(3);
});
