<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\ReplayGuards;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\ReplayGuard;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

/**
 * Persists the last-used timestep in the cache store, keyed by model class + id.
 *
 * For multi-node hosts point this at an atomic store (Redis, Memcached, database)
 * so concurrent challenges cannot both observe a stale timestep.
 */
final class CacheReplayGuard implements ReplayGuard
{
    public function __construct(
        private readonly CacheFactory $cache,
        private readonly ?string $store,
        private readonly int $ttl,
    ) {}

    public function latestTimestep(TwoFactorAuthenticatable&Model $user): ?int
    {
        $value = $this->cache->store($this->store)->get($this->key($user));

        return $value === null ? null : (int) $value;
    }

    public function record(TwoFactorAuthenticatable&Model $user, int $timestep): void
    {
        $this->cache->store($this->store)->put($this->key($user), $timestep, $this->ttl);
    }

    public function reject(TwoFactorAuthenticatable&Model $user, int $timestep): bool
    {
        $latest = $this->latestTimestep($user);

        return $latest !== null && $timestep <= $latest;
    }

    private function key(TwoFactorAuthenticatable&Model $user): string
    {
        return 'two-factor:last:'.$user::class.':'.$user->getKey();
    }
}
