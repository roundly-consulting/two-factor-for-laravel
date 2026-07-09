<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\Enums\HashAlgorithm;
use RoundlyConsulting\TwoFactor\Support\Totp;

it('reproduces every committed TOTP parity vector', function (): void {
    $totp = new Totp(HashAlgorithm::Sha1, 6, 30);

    foreach (parityVectors() as [$secret, $timestamp, $expected]) {
        expect($totp->codeAt($secret, $timestamp))->toBe($expected);
    }
});

it('ships a non-empty parity fixture with two distinct secrets', function (): void {
    $secrets = array_unique(array_column(parityVectors(), 0));

    expect(parityVectors())->not->toBeEmpty()
        ->and($secrets)->toHaveCount(2);
});
