<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Tests\Fixtures;

use Illuminate\Database\Query\Builder as QueryBuilder;

/**
 * A host user whose query builder records every `lockForUpdate()` and the
 * transaction depth it was taken at.
 *
 * SQLite compiles `lockForUpdate()` to an empty string, so no lock ever reaches
 * the wire and no assertion on the emitted SQL can see one. Recording the call
 * at the builder is the only way to pin that the package really does take a
 * pessimistic row lock, inside a transaction, before it reads the recovery-code
 * list it is about to spend.
 */
final class LockRecordingUser extends TwoFactorUser
{
    protected $table = 'users';

    protected function newBaseQueryBuilder(): QueryBuilder
    {
        $connection = $this->getConnection();

        return new LockRecordingBuilder(
            $connection,
            $connection->getQueryGrammar(),
            $connection->getPostProcessor(),
        );
    }
}
