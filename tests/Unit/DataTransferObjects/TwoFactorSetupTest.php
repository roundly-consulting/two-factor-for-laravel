<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\DataTransferObjects\TwoFactorSetup;

it('carries the secret, provisioning uri and recovery codes without a qr', function (): void {
    $setup = new TwoFactorSetup(
        secret: 'JBSWY3DPEHPK3PXP',
        provisioningUri: 'otpauth://totp/Acme:user@acme.io?secret=JBSWY3DPEHPK3PXP',
        recoveryCodes: ['ABCDE-FGHIJ', 'KLMNP-QRSTU'],
    );

    expect($setup->secret)->toBe('JBSWY3DPEHPK3PXP')
        ->and($setup->provisioningUri)->toContain('otpauth://')
        ->and($setup->recoveryCodes)->toHaveCount(2);
});
