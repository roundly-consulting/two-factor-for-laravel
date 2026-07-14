<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Schema\Blueprint;
use RoundlyConsulting\PackageToolkit\Package;
use RoundlyConsulting\PackageToolkit\PackageServiceProvider;
use RoundlyConsulting\TwoFactor\Contracts\ReplayGuard;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorService;
use RoundlyConsulting\TwoFactor\Enums\ReplayGuardMode;
use RoundlyConsulting\TwoFactor\ReplayGuards\CacheReplayGuard;
use RoundlyConsulting\TwoFactor\ReplayGuards\ColumnReplayGuard;
use RoundlyConsulting\TwoFactor\ReplayGuards\NullReplayGuard;
use RoundlyConsulting\TwoFactor\Support\AboutSection;
use RoundlyConsulting\TwoFactor\Support\TwoFactorColumns;

final class TwoFactorServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        // Migrations are publish-only: the package's one migration ALTERs the
        // host's own users table, so it can only ever run from the host's
        // database/migrations directory, stamped with a real timestamp.
        $package
            ->name('two-factor')
            ->hasConfigFile()
            ->hasMigration('add_two_factor_columns_to_users_table')
            ->contributesToAbout(static fn (): array => AboutSection::payload());
    }

    public function register(): void
    {
        parent::register();

        // Registered here, not in boot(): the host's published migration calls
        // twoFactorColumns(), and the migrator can run before boot().
        $this->registerBlueprintMacros();

        $this->app->singleton(ReplayGuard::class, fn (Application $app): ReplayGuard => $this->resolveReplayGuard($app));

        $this->app->singleton(TwoFactorService::class, fn (Application $app): TwoFactor => new TwoFactor(
            $app->make(ReplayGuard::class),
            $this->dispatcher($app),
        ));

        $this->app->alias(TwoFactorService::class, TwoFactor::class);
    }

    private function resolveReplayGuard(Application $app): ReplayGuard
    {
        return match (ReplayGuardMode::fromConfig(config('two-factor.replay_guard'))) {
            ReplayGuardMode::Column => new ColumnReplayGuard,
            ReplayGuardMode::Cache => new CacheReplayGuard(
                $app->make(CacheFactory::class),
                $this->nullableString(config('two-factor.cache.store')),
                (int) config('two-factor.cache.ttl', 86400),
            ),
            ReplayGuardMode::None => new NullReplayGuard,
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
