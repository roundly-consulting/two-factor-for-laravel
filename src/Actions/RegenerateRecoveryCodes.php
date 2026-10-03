<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorService;
use RoundlyConsulting\TwoFactor\Events\RecoveryCodesRegenerated;
use RoundlyConsulting\TwoFactor\Support\ConfigGuard;
use RoundlyConsulting\TwoFactor\Support\RecoveryCodeManager;

/**
 * Replaces the user's recovery codes, returning the new plaintext set to show
 * once.
 */
final readonly class RegenerateRecoveryCodes
{
    public function __construct(
        private TwoFactorService $twoFactor,
        private ?Dispatcher $events = null,
    ) {}

    /**
     * @return list<string>
     */
    public function execute(TwoFactorAuthenticatable&Model $user): array
    {
        $codes = $this->twoFactor->generateRecoveryCodes();

        $manager = new RecoveryCodeManager(
            ConfigGuard::recoveryCodeStorage(),
        );

        $user->setAttribute(ConfigGuard::columns()['recovery_codes'], $manager->forStorage($codes));
        $user->save();

        $this->events?->dispatch(new RecoveryCodesRegenerated($user));

        return $codes;
    }
}
