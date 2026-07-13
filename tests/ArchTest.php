<?php

declare(strict_types=1);

// Guard against any third-party 2FA/crypto/QR dependency by allow-listing only
// the permitted vendor roots. Our own crypto-for-laravel is allowed — it owns the
// OTP/codec/CSPRNG primitives — but any accidental `use` of google2fa,
// bacon-qr-code, a cron parser, etc. fails the suite without naming competitors.
arch('src only uses allowed vendor roots')
    ->expect('RoundlyConsulting\TwoFactor')
    ->toOnlyUse([
        'RoundlyConsulting\TwoFactor',
        'RoundlyConsulting\Crypto',
        'RoundlyConsulting\Enums',
        'Illuminate',
        'Carbon',
        'SensitiveParameter',
        'RuntimeException',
        // native helpers used unqualified
        'app',
        'config',
        'config_path',
        'database_path',
        'decrypt',
        'now',
        '__',
    ]);

arch('no forbidden crypto or qr vendors are imported')
    ->expect(['PragmaRX', 'BaconQrCode', 'Cron'])
    ->not->toBeUsed();

// Every cryptographic primitive comes from crypto-for-laravel — never a
// third-party OTP library, and never a hand-rolled copy back inside this package.
// The HMAC, the constant-time compare, the base32 codec and the CSPRNG must not
// be re-implemented here.
arch('no crypto primitive is re-implemented locally')
    ->expect('RoundlyConsulting\TwoFactor')
    ->not->toUse([
        'hash_hmac',
        'hash_equals',
        'random_bytes',
        'openssl_random_pseudo_bytes',
        'base64_encode',
        'base64_decode',
    ]);

// Only crypto's PUBLIC surface is ours to use: whatever crypto tags `@internal`
// today or tomorrow, this package must not import it, so an internal refactor of
// crypto can never break two-factor.
it('imports no crypto class tagged @internal', function (): void {
    $cryptoSrc = realpath(__DIR__.'/../vendor/roundly-consulting/crypto-for-laravel/src');

    expect($cryptoSrc)->toBeString();

    /** @var list<string> $internal */
    $internal = [];

    /** @var SplFileInfo $file */
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator((string) $cryptoSrc, FilesystemIterator::SKIP_DOTS)) as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }

        $contents = (string) file_get_contents($file->getPathname());

        if (! str_contains($contents, '@internal')) {
            continue;
        }

        if (preg_match('/^namespace\s+([^;]+);/m', $contents, $namespace) === 1) {
            $internal[] = trim($namespace[1]).'\\'.$file->getBasename('.php');
        }
    }

    // Sanity: crypto really does tag something internal (guards a silent no-op).
    expect($internal)->not->toBeEmpty();

    /** @var SplFileInfo $file */
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(realpath(__DIR__.'/../src'), FilesystemIterator::SKIP_DOTS)) as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }

        $contents = (string) file_get_contents($file->getPathname());

        foreach ($internal as $class) {
            expect($contents)->not->toContain($class, "{$file->getPathname()} imports the internal crypto class {$class}");
        }
    }
});

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
