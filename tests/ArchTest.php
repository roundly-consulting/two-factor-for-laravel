<?php

declare(strict_types=1);

// Guard against any third-party 2FA/crypto/QR dependency by allow-listing only
// the permitted vendor roots. Any accidental `use` of google2fa, bacon-qr-code,
// a cron parser, etc. fails the suite — without naming competitors.
arch('src only uses allowed vendor roots')
    ->expect('RoundlyConsulting\TwoFactor')
    ->toOnlyUse([
        'RoundlyConsulting\TwoFactor',
        'RoundlyConsulting\Enums',
        'Illuminate',
        'Carbon',
        'SensitiveParameter',
        'RuntimeException',
        // native helpers used unqualified
        'config',
        'config_path',
        'database_path',
        'decrypt',
        'now',
        '__',
    ]);

arch('no forbidden crypto or qr vendors are imported')
    ->expect(['PragmaRX', 'BaconQrCode', 'Cron', 'Acme'])
    ->not->toBeUsed();

arch('every source file declares strict types')
    ->expect('RoundlyConsulting\TwoFactor')
    ->toUseStrictTypes();

arch('exceptions live in the Exceptions namespace')
    ->expect('RoundlyConsulting\TwoFactor\Exceptions')
    ->toBeClasses()
    ->toExtend('RuntimeException');

arch('the package never uses loose string comparison helpers on codes')
    ->expect('RoundlyConsulting\TwoFactor')
    ->not->toUse(['strcmp', 'md5', 'sha1']);
