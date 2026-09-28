<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\Facades\TwoFactor;

/*
 * The facade contract, pinned: the docblock matches the TwoFactorService contract (the root)
 * and the accessor is its class-string; fake() is real, a TwoFactorService subtype, and takes
 * over DI too; and all five actions under src/Actions are reachable from the facade through
 * `TwoFactor::for($user)` and its `recoveryCodes()` sub-accessor.
 */
it('keeps the facade complete, fakeable and covering every action', function (): void {
    expect(TwoFactor::class)
        ->toDocumentItsRoot()
        ->toBeFakeable()
        ->toReachEveryAction(__DIR__.'/../../src/Actions');
});
