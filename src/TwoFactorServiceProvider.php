<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\TwoFactor\Contracts\ReplayGuard;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorService;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorConfigException;
use RoundlyConsulting\TwoFactor\ReplayGuards\CacheReplayGuard;
use RoundlyConsulting\TwoFactor\ReplayGuards\ColumnReplayGuard;
use RoundlyConsulting\TwoFactor\ReplayGuards\NullReplayGuard;
use RoundlyConsulting\TwoFactor\Support\TwoFactorColumns;

final class TwoFactorServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/two-factor.php', 'two-factor');

        $this->app->singleton(ReplayGuard::class, fn (Application $app): ReplayGuard => $this->resolveReplayGuard($app));

        $this->app->singleton(TwoFactorService::class, fn (Application $app): TwoFactor => new TwoFactor(
            $app->make(ReplayGuard::class),
            $this->dispatcher($app),
        ));

        $this->app->alias(TwoFactorService::class, TwoFactor::class);
    }

    public function boot(): void
    {
        $this->registerBlueprintMacros();

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/two-factor.php' => config_path('two-factor.php'),
            ], 'two-factor-config');

            $this->publishes([
                __DIR__.'/../database/migrations/add_two_factor_columns_to_users_table.php.stub' => database_path(
                    'migrations/'.date('Y_m_d_His').'_add_two_factor_columns_to_users_table.php',
                ),
            ], 'two-factor-migrations');
        }
    }

    private function resolveReplayGuard(Application $app): ReplayGuard
    {
        $mode = config('two-factor.replay_guard');

        return match ($mode) {
            'column' => new ColumnReplayGuard,
            'cache' => new CacheReplayGuard(
                $app->make(CacheFactory::class),
                $this->nullableString(config('two-factor.cache.store')),
                (int) config('two-factor.cache.ttl', 86400),
            ),
            null => new NullReplayGuard,
            default => throw InvalidTwoFactorConfigException::replayGuard((string) $mode),
        };
    }

    private function registerBlueprintMacros(): void
    {
        Blueprint::macro('twoFactorColumns', function (): void {
            /** @var Blueprint $this */
            TwoFactorColumns::add($this);
        });

        Blueprint::macro('dropTwoFactorColumns', function (): void {
            /** @var Blueprint $this */
            TwoFactorColumns::drop($this);
        });
    }

    private function dispatcher(Application $app): ?Dispatcher
    {
        return $app->bound(Dispatcher::class) ? $app->make(Dispatcher::class) : null;
    }

    private function nullableString(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}
