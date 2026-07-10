<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\ReplayGuards;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\ReplayGuard;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

/**
 * Persists the last-used timestep in the cache store, keyed by model class + id.
 *
 * The claim is made atomic with the store's own lock (Redis, Memcached, database,
 * file, array all provide one) so concurrent challenges cannot both observe a
 * stale timestep. Point this at a shared, atomic store on multi-node hosts.
 *
 * Caveat: cache flush/eviction (a deploy, `cache:clear`, LRU pressure) drops the
 * last-used timestep and momentarily reopens the replay window. Use the column
 * guard where that risk is unacceptable.
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
        $value = $this->repository()->get($this->key($user));

        return $value === null ? null : (int) $value;
    }

    public function claim(TwoFactorAuthenticatable&Model $user, int $timestep): bool
    {
        $repository = $this->repository();
        $key = $this->key($user);
        $store = $repository->getStore();

        if ($store instanceof LockProvider) {
            return $store->lock('two-factor:lock:'.$key, 5)
                ->block(5, fn (): bool => $this->attempt($repository, $key, $timestep));
        }

        // Stores without atomic locks fall back to a best-effort read-compare-write.
        return $this->attempt($repository, $key, $timestep);
    }

    private function attempt(Repository $repository, string $key, int $timestep): bool
    {
        $latest = $repository->get($key);
        $latest = $latest === null ? null : (int) $latest;

        if ($latest !== null && $timestep <= $latest) {
            return false;
        }

        $repository->put($key, $timestep, $this->ttl);

        return true;
    }

    private function repository(): Repository
    {
        return $this->cache->store($this->store);
    }

    private function key(TwoFactorAuthenticatable&Model $user): string
    {
        return 'two-factor:last:'.$user::class.':'.$user->getKey();
    }
}
