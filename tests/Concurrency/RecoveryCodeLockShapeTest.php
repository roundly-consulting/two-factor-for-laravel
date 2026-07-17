<?php

declare(strict_types=1);

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use RoundlyConsulting\Testing\Database\DriverMatrix;
use RoundlyConsulting\Testing\Fixtures\LockRecorder;
use RoundlyConsulting\Testing\Fixtures\LockRecordingGrammar;
use RoundlyConsulting\TwoFactor\Actions\StartEnrolment;
use RoundlyConsulting\TwoFactor\DataTransferObjects\TwoFactorSetup;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;
use RoundlyConsulting\TwoFactor\Tests\Fixtures\TwoFactorUser;

/**
 * L — the lock recorders, adopted as **variant B** (the recording grammar).
 *
 * This package already recorded its lock, with a purpose-built builder subclass that
 * captured every `lockForUpdate()` call and the transaction depth it happened at. That
 * fixture is deleted in favour of this, and the reason is the credits bug of 2026-07-16:
 *
 *   credits' overdraft guard applied `lockForUpdate()` to an **aggregate**, emitting
 *   `select sum("amount") … for update`. Postgres rejects that outright — `FOR UPDATE is
 *   not allowed with aggregate functions` — so every guarded spend threw on any real
 *   engine. It shipped because SQLite compiles the lock to an empty string. **credits'
 *   own suite recorded the lock with purpose-built fixtures and still could not see it**:
 *   recording that a lock was *asked for* says nothing about whether the SQL it produced
 *   is legal.
 *
 * That is exactly the blind spot the old fixture here had. Variant B closes it by
 * compiling the lock to a trailing `/* lock-for-update *\/` comment, so the **statement**
 * is observable and can be asserted on — and by driving the same flow on the pgsql leg,
 * where the engine itself is the assertion.
 *
 * **This package's lock does not have the credits shape.** `consumeRecoveryCode()` locks a
 * single row by key — `$user->newQuery()->lockForUpdate()->find($user->getKey())` — which
 * compiles to `select * from users where id = ? limit 1 for update`: legal on Postgres and
 * MySQL alike. The pins below are what keep it that way.
 */
beforeEach(function (): void {
    LockRecorder::flush();
});

/**
 * @return array{0: TwoFactorUser, 1: TwoFactorSetup}
 */
function lockProbeUser(): array
{
    $user = TwoFactorUser::factory()->create();
    $setup = app(StartEnrolment::class)->execute($user);

    $user->setAttribute((string) config('two-factor.columns.confirmed_at'), now());
    $user->save();

    /** @var TwoFactorUser $fresh */
    $fresh = $user->fresh();

    return [$fresh, $setup];
}

/**
 * The shape pin, on sqlite — the only driver that needs a trick to see the lock at all.
 */
it('locks a single user row rather than an aggregate the engine would reject', function (): void {
    $connection = DB::connection();
    $connection->setQueryGrammar(new LockRecordingGrammar($connection));
    LockRecorder::listenForMarkers();

    [$user, $setup] = lockProbeUser();

    LockRecorder::flush();

    expect(TwoFactor::verifyFor($user, $setup->recoveryCodes[0]))->toBeTrue();

    $locks = LockRecorder::recorded();

    expect($locks)->toHaveCount(1)
        ->and($locks[0]['marker'])->toBe('lock-for-update');

    $sql = strtolower($locks[0]['sql']);

    // The credits bug, pinned: a lock over an aggregate is invalid SQL on Postgres and
    // MySQL alike. The locked read must select the row, not aggregate over it.
    expect($sql)->not->toContain('sum(')
        ->not->toContain('count(')
        ->not->toContain('group by')
        // It locks the user row, by key — the row whose recovery-code list is about to be
        // spent. A lock on the wrong row (or on none) leaves the double-spend wide open.
        ->toContain('"users"')
        ->toContain('"users"."id" =')
        // A single row, by key: `limit 1` is what makes this a row lock rather than a
        // table-wide one that would serialise every unrelated verification.
        ->toContain('limit 1')
        // And it is still a lock that serialises: taken inside the consume transaction, at
        // depth 1. Depth is the datum that condemned `LockedUpdate` — a lock one level too
        // deep (in a savepoint released before the write) is a silent non-lock.
        ->and($locks[0]['transactionDepth'])->toBe(1);
})->skip(fn (): bool => DriverMatrix::driver() !== 'sqlite', 'the recording grammar is sqlite-only');

/**
 * The correctness half, on a real engine. The shape pin above proves the statement is
 * legal-looking; only an engine that actually parses `FOR UPDATE` proves it is legal — and
 * only a second session proves it still locks.
 */
it('serialises a rival session on the row it locked', function (): void {
    [$user, $setup] = lockProbeUser();

    config()->set('database.connections.rival', DriverMatrix::connectionConfig('pgsql'));
    DB::purge('rival');
    DB::connection('rival')->statement("set lock_timeout = '400ms'");

    DB::transaction(function () use ($user): void {
        // The guard's locked read, exactly as consumeRecoveryCode() takes it.
        $locked = $user->newQuery()->lockForUpdate()->find($user->getKey());

        expect($locked)->not->toBeNull()
            ->and(DB::transactionLevel())->toBe(1);

        // The control: an UNLOCKED read of the same row from the rival session sails
        // through. Postgres readers never block, so this proves the session is healthy and
        // the timeout below is the row lock — not a dead connection.
        expect(DB::connection('rival')->table('users')->where('id', $user->getKey())->count())->toBe(1);

        // The proof: the same row, requested FOR UPDATE by the rival session, cannot be
        // had while this transaction holds it. Without the lock this returns instantly —
        // and two racing verifications would both read the same stale recovery-code list.
        expect(fn (): mixed => DB::connection('rival')
            ->table('users')
            ->where('id', $user->getKey())
            ->lockForUpdate()
            ->get())
            ->toThrow(QueryException::class, 'lock timeout');
    });

    // Released on commit, never before: a lock held too briefly is as broken as no lock.
    expect(DB::connection('rival')->table('users')->lockForUpdate()->get())->toHaveCount(1);

    // And the flow itself still works on this engine end to end.
    expect(TwoFactor::verifyFor($user->fresh(), $setup->recoveryCodes[0]))->toBeTrue();
})->skip(fn (): bool => DriverMatrix::driver() !== 'pgsql', 'the lock is only observable on a real engine');
