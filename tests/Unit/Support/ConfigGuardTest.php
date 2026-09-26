<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\DataTransferObjects\AttemptLimit;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorConfigException;
use RoundlyConsulting\TwoFactor\Support\ConfigGuard;

it('returns the configured values within bounds', function (): void {
    config([
        'two-factor.digits' => 8,
        'two-factor.period' => 60,
        'two-factor.window' => 2,
        'two-factor.secret_length' => 20,
    ]);

    expect(ConfigGuard::digits())->toBe(8)
        ->and(ConfigGuard::period())->toBe(60)
        ->and(ConfigGuard::window())->toBe(2)
        ->and(ConfigGuard::secretLength())->toBe(20);
});

it('rejects an out-of-range digit count', function (int $digits): void {
    config(['two-factor.digits' => $digits]);
    ConfigGuard::digits();
})->with([5, 9, 0])->throws(InvalidTwoFactorConfigException::class);

it('rejects an out-of-range period', function (int $period): void {
    config(['two-factor.period' => $period]);
    ConfigGuard::period();
})->with([14, 121, 0])->throws(InvalidTwoFactorConfigException::class);

it('rejects an out-of-range window', function (int $window): void {
    config(['two-factor.window' => $window]);
    ConfigGuard::window();
})->with([-1, 3, 30])->throws(InvalidTwoFactorConfigException::class);

it('rejects a secret shorter than 16 characters', function (int $length): void {
    config(['two-factor.secret_length' => $length]);
    ConfigGuard::secretLength();
})->with([0, 8, 15])->throws(InvalidTwoFactorConfigException::class);

it('resolves the attempt limit from config', function (): void {
    config(['two-factor.attempts' => ['max' => 3, 'decay' => 90]]);

    $limit = ConfigGuard::attemptLimit();

    expect($limit)->toBeInstanceOf(AttemptLimit::class)
        ->and($limit->max)->toBe(3)
        ->and($limit->decay)->toBe(90);
});

it('returns null when the limiter is disabled', function (): void {
    config(['two-factor.attempts' => null]);

    expect(ConfigGuard::attemptLimit())->toBeNull();
});

it('rejects a non-positive attempt budget', function (array $attempts): void {
    config(['two-factor.attempts' => $attempts]);
    ConfigGuard::attemptLimit();
})->with([
    'zero max' => [['max' => 0, 'decay' => 60]],
    'zero decay' => [['max' => 5, 'decay' => 0]],
])->throws(InvalidTwoFactorConfigException::class);

it('resolves the default issuer from config, then the app name', function (): void {
    config(['two-factor.issuer' => 'Acme', 'app.name' => 'App']);
    expect(ConfigGuard::issuer())->toBe('Acme');

    config(['two-factor.issuer' => null]);
    expect(ConfigGuard::issuer())->toBe('App');
});

it('treats a blank configured issuer as unset', function (string $blank): void {
    // `TWO_FACTOR_ISSUER=` in a .env is an empty string, not null — it must not
    // brand every authenticator entry with an empty issuer.
    config(['two-factor.issuer' => $blank, 'app.name' => 'App']);

    expect(ConfigGuard::issuer())->toBe('App');
})->with(['empty' => [''], 'whitespace' => ['   ']]);

it('prefers a non-blank caller issuer and ignores a blank one', function (): void {
    config(['two-factor.issuer' => 'Acme', 'app.name' => 'App']);

    expect(ConfigGuard::issuer('Tenant'))->toBe('Tenant')
        ->and(ConfigGuard::issuer(''))->toBe('Acme')
        ->and(ConfigGuard::issuer('  '))->toBe('Acme')
        ->and(ConfigGuard::issuer(null))->toBe('Acme');
});
