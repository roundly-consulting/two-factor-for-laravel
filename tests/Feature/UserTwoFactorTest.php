<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\TwoFactor\Actions\AttemptTwoFactorCode;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorService;
use RoundlyConsulting\TwoFactor\DataTransferObjects\TwoFactorStatus;
use RoundlyConsulting\TwoFactor\Enums\TwoFactorMethod;
use RoundlyConsulting\TwoFactor\Events\RecoveryCodesRegenerated;
use RoundlyConsulting\TwoFactor\Events\TwoFactorDisabled;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorCodeException;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorAlreadyEnabledException;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;
use RoundlyConsulting\TwoFactor\Tests\Fixtures\TwoFactorUser;
use RoundlyConsulting\TwoFactor\TwoFactorManager;
use RoundlyConsulting\TwoFactor\UserRecoveryCodes;
use RoundlyConsulting\TwoFactor\UserTwoFactor;

afterEach(function (): void {
    Carbon::setTestNow();
});

it('runs the whole lifecycle through TwoFactor::for()', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    $user = TwoFactorUser::factory()->create(['email' => 'ada@example.com']);
    $twoFactor = TwoFactor::for($user);

    expect($twoFactor)->toBeInstanceOf(UserTwoFactor::class);

    $setup = $twoFactor->start(issuer: 'Acme');

    expect($setup->issuer)->toBe('Acme')
        ->and($setup->provisioningUri)->toContain('issuer=Acme')->toContain('ada%40example.com')
        ->and($twoFactor->status())->toEqual(new TwoFactorStatus(enabled: false, pending: true, recoveryCodesRemaining: 8, confirmedAt: null));

    $twoFactor->confirm(TwoFactor::currentCode($setup->secret));

    $status = TwoFactor::for($user->fresh())->status();

    expect($status->enabled)->toBeTrue()
        ->and($status->pending)->toBeFalse()
        ->and($status->recoveryCodesRemaining)->toBe(8)
        ->and($status->confirmedAt)->toBeInstanceOf(CarbonImmutable::class)
        ->and($status->confirmedAt?->getTimestamp())->toBe(1_700_000_000);

    // The confirming timestep is spent: the next step's code passes, via TOTP.
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_030));

    expect(TwoFactor::for($user->fresh())->attempt(TwoFactor::currentCode($setup->secret)))
        ->verified->toBeTrue()
        ->method->toBe(TwoFactorMethod::Totp);

    expect(TwoFactor::for($user->fresh())->attempt($setup->recoveryCodes[0]))
        ->verified->toBeTrue()
        ->method->toBe(TwoFactorMethod::RecoveryCode)
        ->remainingRecoveryCodes->toBe(7)
        ->and(TwoFactor::for($user->fresh())->recoveryCodes()->remaining())->toBe(7);

    TwoFactor::for($user->fresh())->disable();

    expect(TwoFactor::for($user->fresh())->status())
        ->toEqual(new TwoFactorStatus(enabled: false, pending: false, recoveryCodesRemaining: 0, confirmedAt: null));
});

it('uses the label passed to start()', function (): void {
    $setup = TwoFactor::for(TwoFactorUser::factory()->create())->start('ops-console');

    expect($setup->provisioningUri)->toContain('ops-console');
});

it('refuses to start over an enabled enrolment', function (): void {
    $user = TwoFactorUser::factory()->create();
    $setup = TwoFactor::for($user)->start();
    TwoFactor::for($user)->confirm(TwoFactor::currentCode($setup->secret));

    TwoFactor::for($user->fresh())->start();
})->throws(TwoFactorAlreadyEnabledException::class);

it('refuses a wrong confirmation code', function (): void {
    $user = TwoFactorUser::factory()->create();
    TwoFactor::for($user)->start();

    TwoFactor::for($user->fresh())->confirm('000000');
})->throws(InvalidTwoFactorCodeException::class);

it('reports a user who never enrolled as off', function (): void {
    expect(TwoFactor::for(TwoFactorUser::factory()->create())->status())
        ->toEqual(new TwoFactorStatus(enabled: false, pending: false, recoveryCodesRemaining: 0, confirmedAt: null));
});

it('reads an uncast confirmed_at column', function (): void {
    $user = TwoFactorUser::factory()->create();
    $setup = TwoFactor::for($user)->start();
    TwoFactor::for($user)->confirm(TwoFactor::currentCode($setup->secret));

    // A host model that never spread twoFactorCasts(): the timestamp arrives as a string.
    $uncast = new class extends TwoFactorUser
    {
        protected function casts(): array
        {
            return [];
        }
    };

    /** @var TwoFactorUser $row */
    $row = $uncast->newQuery()->findOrFail($user->getKey());

    expect(TwoFactor::for($row)->status()->confirmedAt)->toBeInstanceOf(CarbonImmutable::class);
});

it('regenerates recovery codes through the sub-accessor', function (): void {
    Event::fake([RecoveryCodesRegenerated::class]);
    $user = TwoFactorUser::factory()->create();
    $setup = TwoFactor::for($user)->start();

    $codes = TwoFactor::for($user)->recoveryCodes();

    expect($codes)->toBeInstanceOf(UserRecoveryCodes::class);

    $fresh = $codes->regenerate();

    expect($fresh)->toHaveCount(8)
        ->and(array_intersect($fresh, $setup->recoveryCodes))->toBe([])
        ->and(TwoFactor::for($user->fresh())->recoveryCodes()->remaining())->toBe(8);
    Event::assertDispatched(RecoveryCodesRegenerated::class);
});

it('serves the same API to an injected TwoFactorService', function (): void {
    Event::fake([TwoFactorDisabled::class]);
    $service = app(TwoFactorService::class);
    $user = TwoFactorUser::factory()->create();

    expect($service)->toBeInstanceOf(TwoFactorManager::class)
        ->and(app(TwoFactorService::class))->toBe($service);

    $service->for($user)->start();

    expect($service->for($user->fresh())->status()->pending)->toBeTrue();

    $service->for($user->fresh())->disable();

    Event::assertDispatched(TwoFactorDisabled::class);
});

it('runs the attempt action on its own', function (): void {
    Carbon::setTestNow(Carbon::createFromTimestamp(1_700_000_000));
    $user = TwoFactorUser::factory()->create();
    $setup = TwoFactor::for($user)->start();
    TwoFactor::for($user)->confirm(TwoFactor::currentCode($setup->secret));

    $action = app(AttemptTwoFactorCode::class);

    expect($action->execute($user->fresh(), $setup->recoveryCodes[1]))
        ->verified->toBeTrue()
        ->method->toBe(TwoFactorMethod::RecoveryCode)
        ->and($action->execute($user->fresh(), $setup->recoveryCodes[1])->verified)->toBeFalse();
});
