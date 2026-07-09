<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\Actions\StartEnrolment;
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
