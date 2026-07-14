<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use RoundlyConsulting\TwoFactor\Actions\StartEnrolment;
use RoundlyConsulting\TwoFactor\Tests\Fixtures\TwoFactorUser;

/**
 * `php artisan about` is a diagnostic, not a disclosure. For a 2FA package that
 * means the section reports parameters, switches and presence — never a secret,
 * a recovery code, the issuer, or the cache store's name.
 */
function aboutOutput(): string
{
    // Artisan::output() is the only reader that returns the rendered text; the
    // console kernel's own output() answers '' here.
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

it('renders the configured switches rather than their internals', function (): void {
    config([
        'two-factor.replay_guard' => 'cache',
        'two-factor.cache.store' => 'redis-2fa',
        'two-factor.attempts' => null,
        'two-factor.issuer' => 'Acme Bank',
    ]);

    $output = aboutOutput();

    expect($output)->toContain('cache (custom store)')
        ->and($output)->toContain('OFF (host throttling)')
        ->and($output)->toContain('SET')
        // The store name and the issuer are the host's business, not the
        // console's.
        ->and($output)->not->toContain('redis-2fa')
        ->and($output)->not->toContain('Acme Bank');
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

it('never renders a user secret or recovery code', function (): void {
    $user = TwoFactorUser::factory()->create();
    $setup = app(StartEnrolment::class)->execute($user);

    $output = aboutOutput();

    expect($output)->not->toContain($setup->secret)
        ->and($output)->not->toContain($setup->recoveryCodes[0]);

    // Guard the guard: the section really did render (an empty output would make
    // the two assertions above pass vacuously).
    expect($output)->toContain('Two-factor');
});

it('reports a remapped column map without naming the columns', function (): void {
    config(['two-factor.columns.secret' => 'mfa_secret']);

    $output = aboutOutput();

    expect($output)->toContain('remapped')
        ->and($output)->not->toContain('mfa_secret');
});
