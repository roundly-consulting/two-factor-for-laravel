<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use RoundlyConsulting\Crypto\Otp\OtpAlgorithm;
use RoundlyConsulting\TwoFactor\Actions\StartEnrolment;
use RoundlyConsulting\TwoFactor\Enums\RecoveryCodeStorage;
use RoundlyConsulting\TwoFactor\Enums\ReplayGuardMode;
use RoundlyConsulting\TwoFactor\Tests\Fixtures\TwoFactorUser;

/**
 * `php artisan about` is a diagnostic, not a disclosure. For a 2FA package that means the
 * section reports parameters, switches and presence — never a secret, a recovery code, the
 * issuer, or the cache store's name.
 *
 * The leak checks below go through `toLeakNoSecrets` (A). Purchases #13 is the bug that
 * expectation exists for: the fleet's most credential-heavy `about` section was guarded by
 * negative assertions against `app(Kernel::class)->output()`, which returns `''` — every
 * "does not leak" check was vacuous. This package's own tests were already on the right
 * reader (`Artisan::output()`) and already guarded the guard, so adopting the expectation
 * is not a bug fix here; it is the same proof with the ordering enforced by the assertion
 * rather than by this file remembering to do it: (1) output non-empty, (2) every
 * `mustRender` string present, (3) only then no secret renders.
 */
function aboutOutput(): string
{
    // Artisan::output() is the only reader that returns the rendered text; the console
    // kernel's own output() answers '' here — the #13 trap.
    Artisan::call('about', ['--only' => 'two-factor']);

    return Artisan::output();
}

it('contributes a two-factor section to about', function (): void {
    $output = aboutOutput();

    expect($output)->toContain('Two-factor')
        ->and($output)->toContain('Algorithm')
        ->and($output)->toContain('sha1')
        ->and($output)->toContain('6 digits every 30s')
        ->and($output)->toContain('8 hashed codes')
        ->and($output)->toContain('5 attempts / 60s lockout');
});

/**
 * The whole secret surface of a 2FA package in one capture: the live TOTP secret, a live
 * recovery code, the issuer, the cache store's name and a remapped column name. None of
 * them may render; the parameters around them must.
 */
it('renders the security posture without leaking a secret, an issuer or a store', function (): void {
    // The enrolment runs FIRST, on the shipped column names the fixture table was
    // migrated with. Remapping `two-factor.columns.*` here would be a body-time config
    // change against an already-migrated table — the write would go to a column that does
    // not exist. The remap is covered separately below, by a case that renders without
    // writing.
    $user = TwoFactorUser::factory()->create();
    $setup = app(StartEnrolment::class)->execute($user);

    config([
        'two-factor.replay_guard' => 'cache',
        'two-factor.cache.store' => 'redis-2fa',
        'two-factor.issuer' => 'Acme Bank',
    ]);

    expect('two-factor')->toLeakNoSecrets(
        secrets: [
            // The live enrolment: the TOTP seed and a single-use recovery code are the
            // two things that would hand an attacker the account outright.
            $setup->secret,
            $setup->recoveryCodes[0],
            // The host's deployment detail: which cache store backs the replay guard, and
            // who the issuer is, are the host's business rather than the console's.
            'redis-2fa',
            'Acme Bank',
        ],
        mustRender: [
            // The positive half — the parameters are public by construction (they travel
            // in the otpauth:// URI) and are the reason the section exists.
            'Algorithm',
            'sha1',
            '6 digits every 30s',
            '±1 timesteps',
            '32 base32 chars',
            // Presence, not value: each of these is the safe report standing in for one
            // of the secrets above, so it also proves the line rendered at all rather
            // than being silently absent.
            'SET',
            'cache (custom store)',
        ],
    );
});

/**
 * A remapped column name describes the host's schema; the section reports *that* it was
 * remapped, never to what. Rendering only — no row is written, so the remap can safely be
 * set after the fixture table was migrated.
 */
it('reports a remapped column map without naming the columns', function (): void {
    config(['two-factor.columns.secret' => 'mfa_secret']);

    expect('two-factor')->toLeakNoSecrets(
        secrets: ['mfa_secret'],
        mustRender: ['Columns', 'remapped'],
    );
});

it('reports every replay-guard mode', function (?string $mode, ?string $store, string $expected): void {
    config(['two-factor.replay_guard' => $mode, 'two-factor.cache.store' => $store]);

    expect(aboutOutput())->toContain($expected);
})->with([
    'column' => ['column', null, 'column'],
    'cache, default store' => ['cache', null, 'cache (default store)'],
    'none' => ['none', null, 'OFF'],
    'disabled' => [null, null, 'OFF'],
]);

it('reports blank keys as not set, the way the readers resolve them (strict config)', function (): void {
    config([
        'two-factor.algorithm' => '',
        'two-factor.digits' => '',
        'two-factor.period' => ' ',
        'two-factor.window' => '',
        'two-factor.secret_length' => '',
        'two-factor.issuer' => '',
        'two-factor.recovery_codes.count' => '',
        'two-factor.recovery_codes.storage' => '',
        'two-factor.replay_guard' => '',
        'two-factor.attempts' => '',
    ]);

    expect(aboutOutput())->toMatch('/Algorithm\s*\.*\s*sha1/')
        ->toContain('6 digits every 30s')
        ->toContain('±1 timesteps')
        ->toContain('32 base32 chars')
        ->toContain('DEFAULT (app.name)')
        ->toContain('8 hashed codes')
        ->toMatch('/Replay guard\s*\.*\s*column/')
        ->toContain('5 attempts / 60s lockout');
});

it('reports blank column names as the default map (strict config)', function (): void {
    config(['two-factor.columns' => ['secret' => '', 'confirmed_at' => ' ']]);

    expect(aboutOutput())->toMatch('/Columns\s*\.*\s*default/');
});

it('reports a blank cache store as the default store (strict config)', function (): void {
    config(['two-factor.replay_guard' => 'cache', 'two-factor.cache.store' => '']);

    expect(aboutOutput())->toContain('cache (default store)');
});

it('reports a disabled attempt limiter as the host taking over', function (): void {
    config(['two-factor.attempts' => null]);

    expect(aboutOutput())->toContain('OFF (host throttling)');
});

/**
 * Enum cases are a documented config value the readers accept, so the diagnostic has to
 * render them as the readers resolve them — never crash `about` or print the default.
 */
it('reports enum-case config values as the readers resolve them', function (string $key, mixed $value, string $expected): void {
    config([$key => $value]);

    expect(aboutOutput())->toMatch($expected);
})->with([
    'replay guard Column' => ['two-factor.replay_guard', ReplayGuardMode::Column, '/Replay guard\s*\.*\s*column/'],
    'replay guard Cache' => ['two-factor.replay_guard', ReplayGuardMode::Cache, '/Replay guard\s*\.*\s*cache \(default store\)/'],
    'replay guard None' => ['two-factor.replay_guard', ReplayGuardMode::None, '/Replay guard\s*\.*\s*OFF/'],
    'algorithm Sha512' => ['two-factor.algorithm', OtpAlgorithm::Sha512, '/Algorithm\s*\.*\s*sha512/'],
    'storage Encrypted' => ['two-factor.recovery_codes.storage', RecoveryCodeStorage::Encrypted, '/8 encrypted codes/'],
]);
