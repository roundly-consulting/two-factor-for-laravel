<?php

declare(strict_types=1);

/**
 * The config file and the code that reads it are one contract, and it breaks in both
 * directions:
 *
 *  - forward — a key the code READS but the file does not SHIP silently resolves to
 *    null. For a 2FA package that means an empty algorithm or a missing column name.
 *    This is shops #18, whose whole store-credit feature read `shops.payments.*` while
 *    the file shipped `payment.*`; 330 tests stayed green because the suite set the same
 *    wrong key.
 *  - reverse — a key the file SHIPS and documents but no code READS is a dead feature: a
 *    host configures it, nothing happens, and only the docs claim otherwise. That is
 *    media #27's `max_file_size` cap that never applied and alerts #24's thrice-documented
 *    `escalation` key.
 *
 * This replaces ~130 lines of hand-rolled tokenizer that did the same job for this package
 * alone. The shared assertion is strictly stronger: it also counts reads through an
 * injected config Repository and flags an interpolated `config("two-factor.{$x}")` rather
 * than silently ignoring it.
 */
it('ships exactly the config keys it reads', function (): void {
    expect(__DIR__.'/../../config/two-factor.php')->toSatisfyConfigContract(__DIR__.'/../../src', [
        // `two-factor.columns` is read whole and indexed in PHP (the column map is handed
        // to the Blueprint macro as an array), so its leaves are reached through the
        // parent read rather than by a `config('two-factor.columns.secret')` literal.
        'sectionVariables' => [
            'TwoFactorColumns.php' => ['$columns' => 'two-factor.columns'],
        ],
    ]);
});
