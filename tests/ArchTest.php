<?php

declare(strict_types=1);

use RoundlyConsulting\Testing\Arch\ArchPresets;
use RoundlyConsulting\TwoFactor\UserRecoveryCodes;
use RoundlyConsulting\TwoFactor\UserTwoFactor;

/**
 * The seven presets replace this package's hand-written generic rules. The rules that
 * are genuinely two-factor's own — the vendor allow-list, the crypto @internal pin, the
 * exception shape — have no preset equivalent and are kept below.
 */
ArchPresets::strictTypes('RoundlyConsulting\TwoFactor');

/**
 * Two-factor swaps no model (it works on the *host's* user model, which the host already
 * owns) and ships no config key inviting a subclass, so `swappableModelsAreNotFinal` is not
 * adopted — there is no swappable model to pin.
 *
 * The two exemptions are the `TwoFactor::for($user)` handles: `TwoFactor::fake()` returns
 * recording subclasses of them (`Testing\Recording*`), so every enrolment write through
 * the facade or the model verbs is seen by the fake.
 */
ArchPresets::finalByDefault('RoundlyConsulting\TwoFactor', [UserTwoFactor::class, UserRecoveryCodes::class]);

/**
 * The `HasTwoFactorAuthentication` verbs go through `TwoFactor::for($this)`, never an
 * action, so the fake sees every call.
 */
ArchPresets::modelsGoThroughTheFacade('RoundlyConsulting\TwoFactor');

/**
 * Every cryptographic primitive comes from crypto-for-laravel — never a third-party OTP
 * library, and never a hand-rolled copy back inside this package. The HMAC, the base32
 * codec and the CSPRNG must not be re-implemented here.
 *
 * This replaces the bespoke ban list that stood here, which also banned `hash_equals`.
 * That ban is deliberately NOT carried over: `hash_equals` IS PHP's constant-time
 * compare, not a re-implementation of one, and it has no algorithm or key to centralise.
 * Banning it pushes a caller toward `$a === $b` — a timing leak in exactly the code that
 * compares a TOTP code. The fleet removed it from the shared preset on 2026-07-17; this
 * package was one of six still banning it in a local list that never read the shared one.
 */
/**
 * NO EXEMPTIONS — which is the whole point of this call, and the reason the refactor
 * behind it was worth doing.
 *
 * `RecoveryCodeManager::segment()` used to draw recovery-code characters with a local
 * `random_int(0, $max)` loop that was, line for line, crypto-for-laravel's
 * `Random\Token::fromAlphabet()`. It now calls exactly that, so the class needs no
 * exemption and this preset covers it directly.
 *
 * The restored coverage is the real gain, not the shorter generator. Pest's exemptions are
 * scoped to a **class**, not a function: exempting `RecoveryCodeManager` to permit its one
 * `random_int` blinded the most security-sensitive class in the package — the generator for
 * the codes that bypass 2FA entirely — to every other banned primitive. A token-scan
 * re-imposing the rest used to stand here to buy that back. Routing through crypto deleted
 * the exemption and that workaround together.
 */
ArchPresets::noLocalCryptoPrimitives('RoundlyConsulting\TwoFactor');

/**
 * `modelsResolveThroughSeam` is NOT adopted, with cause. Two-factor ships no Eloquent
 * model and no `*_model` config key — it operates on the host's own user model, passed in
 * — so both halves of the preset are structurally inert: there is no seam directory to
 * police and no swap literal to find outside one. This matches jwt's rejection (same
 * shape, same reason) rather than credits' adoption.
 */

/**
 * The Dependency Policy as a test. No `alsoAllow`: two-factor's `require` ships only
 * php/illuminate/roundly, and the workflow installs test tooling with `--dev`. If this
 * goes red the shipped graph is wrong — never widen the allow-list to quiet it.
 */
ArchPresets::runtimeRequireIsWhitelisted(__DIR__.'/../composer.json');

ArchPresets::noDebuggingLeftovers();

/**
 * Bespoke, kept — no preset equivalent.
 *
 * Guard against any third-party 2FA/crypto/QR dependency by allow-listing only the
 * permitted vendor roots. Our own crypto-for-laravel is allowed — it owns the
 * OTP/codec/CSPRNG primitives — but any accidental `use` of a third-party OTP library,
 * QR encoder or cron parser fails the suite without naming competitors.
 *
 * `RoundlyConsulting\Qr` is deliberately absent — two-factor emits the URI, rendering is
 * the host's/auth's (cross-qr-for-laravel.md, Option B).
 */
arch('src only uses allowed vendor roots')
    ->expect('RoundlyConsulting\TwoFactor')
    ->toOnlyUse([
        'RoundlyConsulting\TwoFactor',
        'RoundlyConsulting\Crypto',
        'RoundlyConsulting\Enums',
        'RoundlyConsulting\PackageToolkit',
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
    ->expect(['PragmaRX', 'BaconQrCode', 'Endroid', 'chillerlan', 'SimpleSoftwareIO', 'Cron'])
    ->not->toBeUsed();

/**
 * Bespoke, kept — no preset equivalent. Only crypto's PUBLIC surface is ours to use:
 * whatever crypto tags `@internal` today or tomorrow, this package must not import it, so
 * an internal refactor of crypto can never break two-factor.
 */
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
            // This read `expect($contents)->not->toContain($class, "…message…")`, and that
            // call is **vacuous**: Pest's `toContain` is variadic, so the message was taken
            // as a SECOND NEEDLE and `not->toContain(a, b)` passes whenever a and b are not
            // both present — which, for a message that never appears in source, is always.
            // The test could not fail. Asserted through `str_contains` so the message stays
            // a message.
            expect(str_contains($contents, $class))->toBeFalse(
                "{$file->getPathname()} imports the internal crypto class {$class}",
            );
        }
    }
});

/**
 * Bespoke, kept — no preset equivalent.
 */
arch('exceptions live in the Exceptions namespace')
    ->expect('RoundlyConsulting\TwoFactor\Exceptions')
    ->toBeClasses()
    ->toExtend('RuntimeException');

arch('the package never uses loose string comparison helpers on codes')
    ->expect('RoundlyConsulting\TwoFactor')
    ->not->toUse(['strcmp', 'md5', 'sha1']);
