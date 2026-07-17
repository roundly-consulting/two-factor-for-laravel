<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Tests;

use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\Crypto\CryptoServiceProvider;
use RoundlyConsulting\Testing\PackageTestCase;
use RoundlyConsulting\TwoFactor\TwoFactorServiceProvider;

abstract class TestCase extends PackageTestCase
{
    /**
     * Every provider two-factor hard-requires, in registration order. A host
     * auto-discovers these; the suite must list them or the test environment is a
     * fiction. Crypto is not optional here — it owns the HMAC, the base32 codec and
     * the CSPRNG this package's TOTP is built from.
     *
     * @return list<class-string<ServiceProvider>>
     */
    protected function packageProviders(): array
    {
        return [
            CryptoServiceProvider::class,
            TwoFactorServiceProvider::class,
        ];
    }

    /**
     * The package ships no migration that creates anything — its only migration is a
     * publish-only stub ALTERing the host's users table — so the sole source here is
     * the host-owned `users` fixture the 2FA columns hang off.
     *
     * @return list<class-string<ServiceProvider>|string>
     */
    protected function migrationSources(): array
    {
        return [__DIR__.'/database/migrations'];
    }
}
