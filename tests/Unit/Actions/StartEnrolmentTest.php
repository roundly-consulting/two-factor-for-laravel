<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\Actions\StartEnrolment;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;
use RoundlyConsulting\TwoFactor\Tests\Fixtures\TwoFactorUser;

it('uses the user email as the provisioning label by default', function (): void {
    $user = TwoFactorUser::factory()->create(['email' => 'jane@acme.io']);

    $setup = app(StartEnrolment::class)->execute($user);

    expect($setup->provisioningUri)->toContain(rawurlencode('jane@acme.io'));
});

it('accepts an explicit provisioning label', function (): void {
    $user = TwoFactorUser::factory()->create(['email' => 'jane@acme.io']);

    $setup = app(StartEnrolment::class)->execute($user, 'custom-label');

    expect($setup->provisioningUri)->toContain('custom-label');
});

it('falls back to the primary key when the user has no email', function (): void {
    $user = TwoFactorUser::factory()->create(['email' => null]);

    $setup = app(StartEnrolment::class)->execute($user);

    expect($setup->provisioningUri)->toContain(':'.$user->getKey().'?');
});

it('brands the provisioning uri with an explicit issuer', function (): void {
    config(['two-factor.issuer' => 'Configured Issuer']);
    $user = TwoFactorUser::factory()->create(['email' => 'jane@acme.io']);

    $setup = app(StartEnrolment::class)->execute($user, issuer: 'Acme Clients');

    // The explicit issuer wins over config — in both the label prefix and the parameter.
    expect($setup->issuer)->toBe('Acme Clients')
        ->and($setup->provisioningUri)->toStartWith('otpauth://totp/Acme%20Clients:jane%40acme.io?')
        ->and($setup->provisioningUri)->toContain('issuer=Acme%20Clients')
        ->and($setup->provisioningUri)->not->toContain('Configured');
});

it('falls back to the configured issuer when none is passed', function (): void {
    config(['two-factor.issuer' => 'Configured Issuer']);
    $user = TwoFactorUser::factory()->create();

    $setup = app(StartEnrolment::class)->execute($user);

    expect($setup->issuer)->toBe('Configured Issuer')
        ->and($setup->provisioningUri)->toContain('issuer=Configured%20Issuer');
});

it('falls back to the app name when no issuer is configured or passed', function (): void {
    config(['two-factor.issuer' => null, 'app.name' => 'Fallback App']);
    $user = TwoFactorUser::factory()->create();

    $setup = app(StartEnrolment::class)->execute($user);

    expect($setup->issuer)->toBe('Fallback App')
        ->and($setup->provisioningUri)->toStartWith('otpauth://totp/Fallback%20App:');
});

it('keeps the setup issuer and the uri in agreement under the fake', function (): void {
    TwoFactor::fake();
    config(['two-factor.issuer' => 'Configured Issuer']);
    $user = TwoFactorUser::factory()->create();

    $setup = app(StartEnrolment::class)->execute($user);

    // The action resolves the issuer itself, so the fake's own default never leaks in.
    expect($setup->issuer)->toBe('Configured Issuer')
        ->and($setup->provisioningUri)->toContain('issuer=Configured%20Issuer');
});

it('falls back to the configured issuer when a blank one is passed', function (): void {
    config(['two-factor.issuer' => 'Configured Issuer']);
    $user = TwoFactorUser::factory()->create(['email' => 'jane@acme.io']);

    $setup = app(StartEnrolment::class)->execute($user, issuer: '');

    expect($setup->issuer)->toBe('Configured Issuer')
        ->and($setup->provisioningUri)->toStartWith('otpauth://totp/Configured%20Issuer:jane%40acme.io?');
});
