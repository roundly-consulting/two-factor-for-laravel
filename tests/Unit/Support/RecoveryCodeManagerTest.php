<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Hash;
use RoundlyConsulting\TwoFactor\Enums\RecoveryCodeStorage;
use RoundlyConsulting\TwoFactor\Support\RecoveryCodeManager;

it('generates the requested count of correctly formatted codes', function (): void {
    $codes = (new RecoveryCodeManager)->generate(8);

    expect($codes)->toHaveCount(8);

    foreach ($codes as $code) {
        expect($code)->toMatch('/^[A-Z0-9]{5}-[A-Z0-9]{5}$/');
    }
});

it('stores plaintext codes verbatim in encrypted mode', function (): void {
    $manager = new RecoveryCodeManager(RecoveryCodeStorage::Encrypted);
    $codes = ['ABCDE-FGHIJ', 'KLMNP-QRSTU'];

    expect($manager->forStorage($codes))->toBe($codes);
});

it('stores hashes in hashed mode', function (): void {
    $manager = new RecoveryCodeManager(RecoveryCodeStorage::Hashed);
    $stored = $manager->forStorage(['ABCDE-FGHIJ']);

    expect($stored[0])->not->toBe('ABCDE-FGHIJ')
        ->and(Hash::check('ABCDE-FGHIJ', $stored[0]))->toBeTrue();
});

it('consumes exactly one matching code in encrypted mode', function (): void {
    $manager = new RecoveryCodeManager(RecoveryCodeStorage::Encrypted);
    $stored = ['ABCDE-FGHIJ', 'KLMNP-QRSTU', 'VWXYZ-01234'];

    $remaining = $manager->consume($stored, 'KLMNP-QRSTU');

    expect($remaining)->toBe(['ABCDE-FGHIJ', 'VWXYZ-01234']);
});

it('returns null and leaves the list intact when nothing matches', function (): void {
    $manager = new RecoveryCodeManager(RecoveryCodeStorage::Encrypted);
    $stored = ['ABCDE-FGHIJ'];

    expect($manager->consume($stored, 'NOPE1-NOPE2'))->toBeNull();
});

it('consumes a matching code in hashed mode', function (): void {
    $manager = new RecoveryCodeManager(RecoveryCodeStorage::Hashed);
    $stored = $manager->forStorage(['ABCDE-FGHIJ', 'KLMNP-QRSTU']);

    $remaining = $manager->consume($stored, 'ABCDE-FGHIJ');

    expect($remaining)->toHaveCount(1)
        ->and(Hash::check('KLMNP-QRSTU', $remaining[0]))->toBeTrue();
});

it('generates unique codes', function (): void {
    $codes = (new RecoveryCodeManager)->generate(8);

    expect(array_unique($codes))->toHaveCount(8);
});
