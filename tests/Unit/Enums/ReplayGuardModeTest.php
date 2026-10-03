<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\Enums\ReplayGuardMode;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorConfigException;

it('exposes the three backed modes', function (): void {
    expect(ReplayGuardMode::values()->all())->toBe(['column', 'cache', 'none']);
});

it('resolves configured mode strings', function (string $value, ReplayGuardMode $mode): void {
    expect(ReplayGuardMode::fromConfig($value))->toBe($mode);
})->with([
    'column' => ['column', ReplayGuardMode::Column],
    'cache' => ['cache', ReplayGuardMode::Cache],
    'none' => ['none', ReplayGuardMode::None],
]);

it('treats a null config value as none', function (): void {
    expect(ReplayGuardMode::fromConfig(null))->toBe(ReplayGuardMode::None);
});

it('reads a blank config value as not set, so the shipped column guard applies', function (string $blank): void {
    expect(ReplayGuardMode::fromConfig($blank))->toBe(ReplayGuardMode::Column);
})->with(['empty' => [''], 'whitespace' => ['  ']]);

it('throws on an unknown mode', function (): void {
    ReplayGuardMode::fromConfig('bogus');
})->throws(InvalidTwoFactorConfigException::class);

it('throws on a non-string mode instead of casting it (strict config)', function (mixed $value): void {
    ReplayGuardMode::fromConfig($value);
})->with([
    'false' => [false],
    'zero' => [0],
    'array' => [['column']],
])->throws(InvalidTwoFactorConfigException::class);
