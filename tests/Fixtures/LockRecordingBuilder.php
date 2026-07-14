<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Tests\Fixtures;

use Illuminate\Database\Query\Builder;

/**
 * Records each `lock()` call (what `lockForUpdate()` delegates to) together with
 * the transaction depth it happened at, so a test can assert the lock was taken
 * *inside* a transaction rather than merely asserting on SQL SQLite never emits.
 */
final class LockRecordingBuilder extends Builder
{
    /**
     * Transaction depth at each recorded lock, oldest first.
     *
     * @var list<int>
     */
    public static array $locks = [];

    public static function reset(): void
    {
        self::$locks = [];
    }

    /**
     * @param  string|bool  $value
     */
    public function lock($value = true): static
    {
        self::$locks[] = $this->getConnection()->transactionLevel();

        parent::lock($value);

        return $this;
    }
}
