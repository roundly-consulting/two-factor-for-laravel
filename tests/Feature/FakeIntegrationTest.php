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
    $user = TwoFactorUser::factory()->withTwoFactor()->create();

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
 * The docs' "Faking two-factor in host tests" block (website docs), run verbatim against
 * the host routes it assumes — keep this copy and the docs identical — so every example in
 * it has to be a complete, passing sequence, not a fragment.
 */
it('runs the documented fake examples as written', function (): void {
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

    $example = <<<'PHP'
        use RoundlyConsulting\TwoFactor\Enums\TwoFactorMethod;
        use RoundlyConsulting\TwoFactor\Facades\TwoFactor;

        // attempt() only passes a user with confirmed 2FA, as in production. Enrol them first:
        // under the fake, enrolment runs for real on its canned secret and accepts any code.
        TwoFactor::fake();
        TwoFactor::for($user)->start();
        TwoFactor::for($user)->confirm('123456');

        // Accept any code (the default) and assert the challenge was verified:
        $fake = TwoFactor::fake()->accept();
        $this->post('/login/2fa', ['code' => '123456'])->assertOk();
        $fake->assertVerifiedFor($user);

        // Reject every code:
        TwoFactor::fake()->reject();
        $this->post('/login/2fa', ['code' => '000000'])->assertStatus(422);

        // Accept only a specific code:
        TwoFactor::fake()->acceptCode('424242');

        // Drive attempt(): pass via a recovery code, report 2 left, assert the method:
        $fake = TwoFactor::fake()->acceptRecoveryCode()->withRemainingRecoveryCodes(2);
        $this->post('/login/2fa', ['code' => 'ABCDE-12345'])->assertOk();
        $fake->assertVerifiedVia(TwoFactorMethod::RecoveryCode);

        // Fail as a replay (VerificationResult::$replayed === true):
        TwoFactor::fake()->replay();

        // Enrolment writes run for real on the fake's canned secret and codes, and are recorded:
        $fake = TwoFactor::fake();
        $this->post('/two-factor/disable')->assertOk();       // or $user->disableTwoFactor()
        $this->post('/two-factor/enable')->assertOk();        // calls TwoFactor::for($user)->start()
        $fake->assertDisabled($user);
        $fake->assertStarted($user);
        $fake->assertNothingRegenerated();
        PHP;

    eval($example);
});
