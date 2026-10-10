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

/*
 * A flat call keeps its secrets out of the facade's own stack frame. Three root methods take a
 * `#[SensitiveParameter]`: currentCode ($secret), verify ($secret, $code) and provisioningUri
 * ($secret). Harmless arguments (timestamp, window, label, issuer) stay visible.
 */
it('redacts the secret arguments of flat facade calls', function (): void {
    expect(TwoFactor::class)->toRedactSensitiveArguments(methods: 3);
});
