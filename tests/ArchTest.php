<?php

declare(strict_types=1);

use RoundlyConsulting\Testing\Arch\ArchPresets;
use RoundlyConsulting\TwoFactor\Support\RecoveryCodeManager;

/**
 * The seven presets replace this package's hand-written generic rules. The rules that
 * are genuinely two-factor's own — the vendor allow-list, the crypto @internal pin, the
 * exception shape — have no preset equivalent and are kept below.
 */
ArchPresets::strictTypes('RoundlyConsulting\TwoFactor');

/**
 * Nothing here is a documented extension point: two-factor swaps no model (it works on
 * the *host's* user model, which the host already owns) and ships no config key inviting
 * a subclass. So `finalByDefault` runs with no exemptions and `swappableModelsAreNotFinal`
 * is not adopted — there is no swappable model to pin, and an empty map would assert
 * nothing while looking like a guard.
 */
ArchPresets::finalByDefault('RoundlyConsulting\TwoFactor');

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
ArchPresets::noLocalCryptoPrimitives('RoundlyConsulting\TwoFactor')
    ->ignoring(RecoveryCodeManager::class);

/**
 * The exemption above is NOT a clean bill of health — it is a deferral, and this test is
 * what stops it costing coverage in the meantime.
 *
 * `RecoveryCodeManager::segment()` draws recovery-code characters with a local
 * `random_int(0, $max)` loop that is **line for line** crypto-for-laravel's
 * `Random\Token::fromAlphabet()`. That is the exact duplication the preset exists to catch,
 * and the bespoke ban list this file used to carry missed it: it banned `random_bytes` but
 * never `random_int`, so the package's own CSPRNG rule had a hole in the one place it
 * mattered — the generator for the codes that bypass 2FA entirely.
 *
 * It is not a *vulnerability*: `random_int` is a CSPRNG and the loop samples uniformly, so
 * the codes are exactly as strong as `fromAlphabet()` would make them. Collapsing it onto
 * crypto is therefore a pure refactor — but it is a refactor of recovery-code generation,
 * which is a crypto change, so it waits for a decision rather than being slipped into an
 * adoption row.
 *
 * The cost of the exemption is that Pest's `->ignoring()` is **class-scoped**, not
 * function-scoped: exempting this class to permit one primitive blinds it to all twenty —
 * in the most security-sensitive class in the package. So the ban is re-imposed here by
 * token scan, minus the one call that is deferred. When the refactor lands, this whole
 * block and the `->ignoring()` above are deleted together.
 */
it('re-imposes every crypto primitive ban on the one exempted class', function (): void {
    $source = (string) file_get_contents(__DIR__.'/../src/Support/RecoveryCodeManager.php');
    $tokens = token_get_all($source);

    /** @var list<string> $called */
    $called = [];

    foreach ($tokens as $index => $token) {
        if (! is_array($token) || $token[0] !== T_STRING) {
            continue;
        }

        // Only a real call — a docblock is a comment token and can never reach here.
        $next = $tokens[$index + 1] ?? null;

        if ($next === '(' || (is_array($next) && $next[0] === T_WHITESPACE && ($tokens[$index + 2] ?? null) === '(')) {
            $called[] = $token[1];
        }
    }

    // Guard the guard: a scanner that matched nothing would pass vacuously. The deferred
    // call must actually be there — the day it goes, this test fails and tells you to
    // delete the exemption rather than quietly protecting nothing.
    expect($called)->toContain('random_int');

    $banned = array_diff(ArchPresets::CRYPTO_PRIMITIVES, ['random_int']);

    foreach ($banned as $primitive) {
        // NOT `expect($called)->not->toContain($primitive, $message)`: Pest's `toContain`
        // is **variadic**, so a "message" passed there is silently taken as a second
        // NEEDLE, and the negation then passes whenever the two needles are not both
        // present — i.e. always. That call is vacuous, and it is vacuous in exactly the
        // shape a reader trusts most (a ban with a helpful message). Asserted through
        // `in_array` so the message stays a message.
        expect(in_array($primitive, $called, true))->toBeFalse(
            "RecoveryCodeManager calls {$primitive}(). It is exempt from the crypto preset only for "
            .'the deferred random_int() refactor; every other primitive still belongs in crypto-for-laravel.',
        );
    }
});

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
    ->expect(['PragmaRX', 'BaconQrCode', 'Cron'])
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
