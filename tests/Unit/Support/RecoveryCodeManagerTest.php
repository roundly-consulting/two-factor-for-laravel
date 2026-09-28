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

/**
 * Codes are printed upper-case in two dashed halves; people type them however they
 * like. A code in this package's own shape is matched case-insensitively, ignoring
 * surrounding whitespace, the dash and spaces between the halves — and a typed
 * letter O (never issued) as the digit zero it was read from.
 */
it('matches a code however the user typed it', function (RecoveryCodeStorage $storage, string $typed): void {
    $manager = new RecoveryCodeManager($storage);
    $stored = $manager->forStorage(['YWNLY-0J5BK', 'KLMNP-QRSTU']);

    $remaining = $manager->consume($stored, $typed);

    expect($remaining)->toHaveCount(1)
        ->and($manager->consume((array) $remaining, 'KLMNP-QRSTU'))->toBe([]);
})->with([RecoveryCodeStorage::Encrypted, RecoveryCodeStorage::Hashed])->with([
    'lowercase' => 'ywnly-0j5bk',
    'surrounding whitespace' => "  YWNLY-0J5BK \n",
    'no dash' => 'YWNLY0J5BK',
    'a space for the dash' => 'ywnly 0j5bk',
    'spaced dash' => 'YWNLY - 0J5BK',
    'letter O for zero' => 'ywnly-oj5bk',
]);

it('still spends a loosely typed code exactly once', function (RecoveryCodeStorage $storage): void {
    $manager = new RecoveryCodeManager($storage);
    $stored = $manager->forStorage(['YWNLY-0J5BK']);

    $remaining = $manager->consume($stored, 'ywnly0j5bk');

    expect($remaining)->toBe([])
        ->and($manager->consume((array) $remaining, 'YWNLY-0J5BK'))->toBeNull();
})->with([RecoveryCodeStorage::Encrypted, RecoveryCodeStorage::Hashed]);

it('does not loosen anything beyond case, spacing and the dash', function (string $typed): void {
    $manager = new RecoveryCodeManager(RecoveryCodeStorage::Encrypted);

    expect($manager->consume(['YWNLY-0J5BK'], $typed))->toBeNull();
})->with([
    'one character short' => 'YWNLY-0J5B',
    'one character long' => 'YWNLY-0J5BKK',
    'a wrong character' => 'YWNLY-0J5BL',
    'a foreign separator' => 'YWNLY_0J5BK',
    'empty' => '',
]);

it('matches an imported code of another shape exactly as stored', function (): void {
    // e.g. a 21-character mixed-case code carried over from another library.
    $manager = new RecoveryCodeManager(RecoveryCodeStorage::Encrypted);
    $stored = ['aBcDeFgHiJ-kLmNoPqRsT'];

    expect($manager->consume($stored, 'ABCDEFGHIJ-KLMNOPQRST'))->toBeNull()
        ->and($manager->consume($stored, ' aBcDeFgHiJ-kLmNoPqRsT '))->toBe([]);
});

it('matches an imported code of the same shape stored in lowercase', function (): void {
    $manager = new RecoveryCodeManager(RecoveryCodeStorage::Encrypted);

    expect($manager->consume(['a1b2c-3d4e5'], 'A1B2C-3D4E5'))->toBe([]);
});
