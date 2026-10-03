<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Otp\OtpAlgorithm;
use RoundlyConsulting\TwoFactor\DataTransferObjects\AttemptLimit;
use RoundlyConsulting\TwoFactor\Enums\RecoveryCodeStorage;
use RoundlyConsulting\TwoFactor\Enums\ReplayGuardMode;
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

it('throws on a junk integer instead of reading it as 0 (strict config)', function (string $key, mixed $junk): void {
    config([$key => $junk]);

    match ($key) {
        'two-factor.digits' => ConfigGuard::digits(),
        'two-factor.period' => ConfigGuard::period(),
        'two-factor.window' => ConfigGuard::window(),
        'two-factor.secret_length' => ConfigGuard::secretLength(),
        'two-factor.recovery_codes.count' => ConfigGuard::recoveryCodeCount(),
        'two-factor.cache.ttl' => ConfigGuard::cacheTtl(),
    };
})->with([
    'window five' => ['two-factor.window', 'five'],
    'window empty' => ['two-factor.window', ''],
    'window float string' => ['two-factor.window', '1.5'],
    'window bool' => ['two-factor.window', false],
    'digits junk' => ['two-factor.digits', '6abc'],
    'period exponent' => ['two-factor.period', '3e1'],
    'secret length junk' => ['two-factor.secret_length', 'long'],
    'recovery count junk' => ['two-factor.recovery_codes.count', 'eight'],
    'cache ttl junk' => ['two-factor.cache.ttl', 'a day'],
])->throws(InvalidTwoFactorConfigException::class);

it('reads canonical integer strings from env (strict config)', function (): void {
    config([
        'two-factor.digits' => '8',
        'two-factor.window' => ' 0 ',
        'two-factor.recovery_codes.count' => '10',
        'two-factor.cache.ttl' => '120',
    ]);

    expect(ConfigGuard::digits())->toBe(8)
        ->and(ConfigGuard::window())->toBe(0)
        ->and(ConfigGuard::recoveryCodeCount())->toBe(10)
        ->and(ConfigGuard::cacheTtl())->toBe(120);
});

it('uses the defaults for absent integer keys (strict config)', function (): void {
    config([
        'two-factor.digits' => null,
        'two-factor.period' => null,
        'two-factor.window' => null,
        'two-factor.secret_length' => null,
        'two-factor.recovery_codes.count' => null,
        'two-factor.cache.ttl' => null,
    ]);

    expect(ConfigGuard::digits())->toBe(6)
        ->and(ConfigGuard::period())->toBe(30)
        ->and(ConfigGuard::window())->toBe(1)
        ->and(ConfigGuard::secretLength())->toBe(32)
        ->and(ConfigGuard::recoveryCodeCount())->toBe(8)
        ->and(ConfigGuard::cacheTtl())->toBe(86_400);
});

it('refuses a recovery-code count or cache ttl below one (strict config)', function (string $key): void {
    config([$key => 0]);

    $key === 'two-factor.cache.ttl' ? ConfigGuard::cacheTtl() : ConfigGuard::recoveryCodeCount();
})->with(['two-factor.recovery_codes.count', 'two-factor.cache.ttl'])->throws(InvalidTwoFactorConfigException::class);

it('throws on a junk attempt budget instead of reading it as 0 (strict config)', function (array $attempts): void {
    config(['two-factor.attempts' => $attempts]);

    ConfigGuard::attemptLimit();
})->with([
    'max five' => [['max' => 'five', 'decay' => 60]],
    'decay junk' => [['max' => 5, 'decay' => '60s']],
])->throws(InvalidTwoFactorConfigException::class);

it('only switches the limiter off with null (strict config)', function (mixed $value): void {
    config(['two-factor.attempts' => $value]);

    ConfigGuard::attemptLimit();
})->with([
    'false' => [false],
    'off' => ['off'],
    'zero' => [0],
])->throws(InvalidTwoFactorConfigException::class, 'attempts');

it('throws on an unknown algorithm and defaults an absent one to sha1 (strict config)', function (): void {
    config(['two-factor.algorithm' => null]);
    expect(ConfigGuard::algorithm())->toBe(OtpAlgorithm::Sha1);

    config(['two-factor.algorithm' => 'SHA256']);
    expect(fn () => ConfigGuard::algorithm())->toThrow(InvalidTwoFactorConfigException::class, 'SHA256');

    config(['two-factor.algorithm' => ['sha1']]);
    expect(fn () => ConfigGuard::algorithm())->toThrow(InvalidTwoFactorConfigException::class);
});

it('throws on a non-string issuer rather than ignoring it (strict config)', function (): void {
    config(['two-factor.issuer' => ['Acme']]);

    ConfigGuard::issuer();
})->throws(InvalidTwoFactorConfigException::class, 'two-factor.issuer');

it('resolves storage and replay modes, defaulting only an absent storage (strict config)', function (): void {
    config(['two-factor.recovery_codes.storage' => null, 'two-factor.replay_guard' => 'cache']);

    expect(ConfigGuard::recoveryCodeStorage())->toBe(RecoveryCodeStorage::Hashed)
        ->and(ConfigGuard::replayGuard())->toBe(ReplayGuardMode::Cache);

    config(['two-factor.recovery_codes.storage' => 'Hashed']);
    expect(fn () => ConfigGuard::recoveryCodeStorage())->toThrow(InvalidTwoFactorConfigException::class, 'Hashed');
});

it('reads the cache store, treating blank as the default store (strict config)', function (): void {
    config(['two-factor.cache.store' => 'redis']);
    expect(ConfigGuard::cacheStore())->toBe('redis');

    config(['two-factor.cache.store' => '']);
    expect(ConfigGuard::cacheStore())->toBeNull();

    config(['two-factor.cache.store' => ['redis']]);
    expect(fn () => ConfigGuard::cacheStore())->toThrow(InvalidTwoFactorConfigException::class, 'two-factor.cache.store');
});

it('resolves remapped columns and defaults absent ones (strict config)', function (): void {
    config(['two-factor.columns' => ['secret' => 'otp_secret']]);

    expect(ConfigGuard::columns())->toBe([
        'secret' => 'otp_secret',
        'recovery_codes' => 'two_factor_recovery_codes',
        'confirmed_at' => 'two_factor_confirmed_at',
        'last_used_timestep' => 'two_factor_last_used_timestep',
    ]);
});

it('throws on a blank or non-string column name (strict config)', function (mixed $columns): void {
    config(['two-factor.columns' => $columns]);

    ConfigGuard::columns();
})->with([
    'blank column' => [['confirmed_at' => '']],
    'array column' => [['secret' => ['x']]],
    'not an array' => ['two_factor_secret'],
])->throws(InvalidTwoFactorConfigException::class);
