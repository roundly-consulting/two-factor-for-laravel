<?php

declare(strict_types=1);

use RoundlyConsulting\PackageToolkit\Enums\DatabaseDriver;
use RoundlyConsulting\Testing\Database\DriverMatrix;

/**
 * The one assertion that makes a lying pgsql leg impossible.
 *
 * It compares the **env-declared** driver (`TESTING_DB_DRIVER`) against what the
 * **connection itself answers**. A leg that exports the location vars but not the driver —
 * or a TestCase that overrides `defineEnvironment()` without calling `parent::` and so
 * never lets `DriverMatrix::configure()` run — quietly runs the whole suite on sqlite and
 * reports green as a "postgres" job. This goes red instead.
 *
 * It is strictly stronger than reading the skip count by hand, because it fires
 * automatically rather than needing someone to notice a number.
 */
it('runs on the driver the leg declared', function (): void {
    expect(DatabaseDriver::current())->toBe(DatabaseDriver::from(DriverMatrix::driver()));
});
