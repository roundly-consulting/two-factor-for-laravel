<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\TwoFactor\Actions\ConfirmEnrolment;
use RoundlyConsulting\TwoFactor\Actions\StartEnrolment;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorService;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;
use RoundlyConsulting\TwoFactor\Testing\TwoFactorFake;
use RoundlyConsulting\TwoFactor\Tests\Fixtures\TwoFactorUser;

it('swaps the bound service for the fake', function (): void {
    $fake = TwoFactor::fake();

    expect($fake)->toBeInstanceOf(TwoFactorFake::class)
        ->and(app(TwoFactorService::class))->toBe($fake);
});

it('drives attempt through the facade without real totp', function (): void {
    $fake = TwoFactor::fake()->accept();
    $user = TwoFactorUser::factory()->create();

    expect(TwoFactor::for($user)->attempt('123456')->verified)->toBeTrue();

    $fake->assertVerifiedFor($user);
});

it('rejects through the facade when told to reject', function (): void {
    TwoFactor::fake()->reject();
    $user = TwoFactorUser::factory()->create();

    expect(TwoFactor::for($user)->attempt('000000')->verified)->toBeFalse();
});

it('lets an action-based enrolment run against the fake with no crypto', function (): void {
    $fake = TwoFactor::fake()->withSecret('FAKESECRET234567');
    $user = TwoFactorUser::factory()->create();

    $setup = app(StartEnrolment::class)->execute($user);
    app(ConfirmEnrolment::class)->execute($user->fresh(), '123456');

    expect($user->fresh()->hasTwoFactorEnabled())->toBeTrue()
        ->and($setup->secret)->toBe('FAKESECRET234567');
    $fake->assertCodeAttempted('123456');
});

/**
 * The README's "Faking two-factor in host tests" block, run verbatim (extracted from
 * README.md) against the host routes it assumes — so every example in it has to be
 * a complete, passing sequence, not a fragment.
 */
it('runs the readme fake examples as written', function (): void {
    $user = TwoFactorUser::factory()->create();

    Route::post('/login/2fa', fn (Request $request) => TwoFactor::for($user)
        ->attempt($request->string('code')->toString())->verified ? response('ok') : abort(422));
    Route::post('/two-factor/enable', function () use ($user) {
        TwoFactor::for($user)->start();

        return response('ok');
    });
    Route::post('/two-factor/disable', function () use ($user) {
        $user->disableTwoFactor();

        return response('ok');
    });

    $readme = (string) file_get_contents(__DIR__.'/../../README.md');
    $section = substr($readme, (int) strpos($readme, '### Faking two-factor in host tests'));

    expect(preg_match('/```php\n(.*?)\n```/s', $section, $match))->toBe(1);

    eval($match[1]);
});
