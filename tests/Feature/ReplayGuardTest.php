<?php

declare(strict_types=1);

use Illuminate\Cache\Repository;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Store;
use RoundlyConsulting\TwoFactor\Contracts\ReplayGuard;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorConfigException;
use RoundlyConsulting\TwoFactor\ReplayGuards\CacheReplayGuard;
use RoundlyConsulting\TwoFactor\ReplayGuards\ColumnReplayGuard;
use RoundlyConsulting\TwoFactor\ReplayGuards\NullReplayGuard;
use RoundlyConsulting\TwoFactor\Tests\Fixtures\TwoFactorUser;

it('resolves the column guard by default', function (): void {
    expect(app(ReplayGuard::class))->toBeInstanceOf(ColumnReplayGuard::class);
});

it('resolves the configured guard implementation', function (?string $mode, string $class): void {
    config(['two-factor.replay_guard' => $mode]);
    app()->forgetInstance(ReplayGuard::class);

    expect(app(ReplayGuard::class))->toBeInstanceOf($class);
})->with([
    'column' => ['column', ColumnReplayGuard::class],
    'cache' => ['cache', CacheReplayGuard::class],
    'null' => [null, NullReplayGuard::class],
]);

it('throws on an invalid guard mode', function (): void {
    config(['two-factor.replay_guard' => 'bogus']);
    app()->forgetInstance(ReplayGuard::class);

    app(ReplayGuard::class);
})->throws(InvalidTwoFactorConfigException::class);

it('claims timesteps monotonically with the column guard', function (): void {
    $guard = new ColumnReplayGuard;
    $user = TwoFactorUser::factory()->create();

    expect($guard->latestTimestep($user))->toBeNull()
        ->and($guard->claim($user, 100))->toBeTrue(); // first claim wins

    expect($guard->latestTimestep($user->fresh()))->toBe(100)
        ->and($guard->claim($user->fresh(), 100))->toBeFalse()  // equal → replay
        ->and($guard->claim($user->fresh(), 99))->toBeFalse()   // earlier → replay
        ->and($guard->claim($user->fresh(), 101))->toBeTrue();  // later → ok
});

it('serializes concurrent same-step claims via a single atomic update', function (): void {
    $guard = new ColumnReplayGuard;
    $user = TwoFactorUser::factory()->create();

    // Two stale in-memory reads of the same row, both seeing a null timestep.
    $a = TwoFactorUser::find($user->getKey());
    $b = TwoFactorUser::find($user->getKey());

    // The conditional UPDATE affects a row for exactly one of them.
    expect($guard->claim($a, 100))->toBeTrue()
        ->and($guard->claim($b, 100))->toBeFalse();
});

it('claims and persists across instances with the cache guard', function (): void {
    $user = TwoFactorUser::factory()->create();

    $first = app()->make(CacheReplayGuard::class, ['store' => 'array', 'ttl' => 3600]);

    expect($first->claim($user, 200))->toBeTrue()      // first claim wins
        ->and($first->claim($user, 200))->toBeFalse()  // same step → replay
        ->and($first->claim($user, 199))->toBeFalse(); // earlier → replay

    $second = app()->make(CacheReplayGuard::class, ['store' => 'array', 'ttl' => 3600]);

    expect($second->latestTimestep($user))->toBe(200)
        ->and($second->claim($user, 201))->toBeTrue(); // later → ok
});

it('claims via a best-effort path on a store without atomic locks', function (): void {
    $store = new class implements Store
    {
        /** @var array<string, mixed> */
        private array $data = [];

        public function get($key): mixed
        {
            return $this->data[$key] ?? null;
        }

        public function many(array $keys): array
        {
            return array_map(fn (string $key): mixed => $this->get($key), array_combine($keys, $keys));
        }

        public function put($key, $value, $seconds): bool
        {
            $this->data[$key] = $value;

            return true;
        }

        public function putMany(array $values, $seconds): bool
        {
            foreach ($values as $key => $value) {
                $this->put($key, $value, $seconds);
            }

            return true;
        }

        public function increment($key, $value = 1): int
        {
            return $this->data[$key] = (int) ($this->data[$key] ?? 0) + $value;
        }

        public function decrement($key, $value = 1): int
        {
            return $this->increment($key, $value * -1);
        }

        public function forever($key, $value): bool
        {
            return $this->put($key, $value, 0);
        }

        public function forget($key): bool
        {
            unset($this->data[$key]);

            return true;
        }

        public function flush(): bool
        {
            $this->data = [];

            return true;
        }

        public function getPrefix(): string
        {
            return '';
        }

        public function touch($key, $ttl): bool
        {
            return array_key_exists($key, $this->data);
        }
    };

    $repository = new Repository($store);
    $factory = new class($repository) implements CacheFactory
    {
        public function __construct(private readonly Repository $repository) {}

        public function store($name = null): Repository
        {
            return $this->repository;
        }
    };

    $guard = new CacheReplayGuard($factory, null, 3600);
    $user = TwoFactorUser::factory()->create();

    expect($guard->claim($user, 100))->toBeTrue()
        ->and($guard->claim($user, 100))->toBeFalse()  // same step → replay
        ->and($guard->claim($user, 101))->toBeTrue();  // later → ok
});

it('always claims with the null guard', function (): void {
    $guard = new NullReplayGuard;
    $user = TwoFactorUser::factory()->create();

    expect($guard->latestTimestep($user))->toBeNull()
        ->and($guard->claim($user, 1))->toBeTrue()
        ->and($guard->claim($user, 999999))->toBeTrue();
});
