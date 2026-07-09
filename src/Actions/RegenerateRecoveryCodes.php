<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;
use RoundlyConsulting\TwoFactor\Enums\RecoveryCodeStorage;
use RoundlyConsulting\TwoFactor\Events\RecoveryCodesRegenerated;
use RoundlyConsulting\TwoFactor\Support\RecoveryCodeManager;
use RoundlyConsulting\TwoFactor\TwoFactor;

/**
 * Replaces the user's recovery codes, returning the new plaintext set to show
 * once.
 */
final class RegenerateRecoveryCodes
{
    public function __construct(
        private readonly TwoFactor $twoFactor,
        private readonly ?Dispatcher $events = null,
    ) {}

    /**
     * @return list<string>
     */
    public function execute(TwoFactorAuthenticatable&Model $user): array
    {
        $codes = $this->twoFactor->generateRecoveryCodes();

        $manager = new RecoveryCodeManager(
            RecoveryCodeStorage::fromConfig((string) config('two-factor.recovery_codes.storage')),
        );

        $user->setAttribute((string) config('two-factor.columns.recovery_codes'), $manager->forStorage($codes));
        $user->save();

        $this->events?->dispatch(new RecoveryCodesRegenerated($user));

        return $codes;
    }
}
