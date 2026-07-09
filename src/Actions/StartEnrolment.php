<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;
use RoundlyConsulting\TwoFactor\DataTransferObjects\TwoFactorSetup;
use RoundlyConsulting\TwoFactor\Enums\RecoveryCodeStorage;
use RoundlyConsulting\TwoFactor\Events\TwoFactorEnrolmentStarted;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorAlreadyEnabledException;
use RoundlyConsulting\TwoFactor\Support\RecoveryCodeManager;
use RoundlyConsulting\TwoFactor\TwoFactor;

/**
 * Begins (or restarts) a pending enrolment: generates a fresh secret + recovery
 * codes, persists them with confirmed_at null, and returns the one-time setup.
 */
final class StartEnrolment
{
    public function __construct(
        private readonly TwoFactor $twoFactor,
        private readonly ?Dispatcher $events = null,
    ) {}

    /**
     * @throws TwoFactorAlreadyEnabledException
     */
    public function execute(TwoFactorAuthenticatable&Model $user, ?string $label = null): TwoFactorSetup
    {
        if ($user->hasTwoFactorEnabled()) {
            throw TwoFactorAlreadyEnabledException::make();
        }

        $secret = $this->twoFactor->generateSecret();
        $codes = $this->twoFactor->generateRecoveryCodes();

        $columns = $this->columns();
        $manager = new RecoveryCodeManager(
            RecoveryCodeStorage::fromConfig((string) config('two-factor.recovery_codes.storage')),
        );

        $user->setAttribute($columns['secret'], $secret);
        $user->setAttribute($columns['recovery_codes'], $manager->forStorage($codes));
        $user->setAttribute($columns['confirmed_at'], null);
        $user->setAttribute($columns['last_used_timestep'], null);
        $user->save();

        $this->events?->dispatch(new TwoFactorEnrolmentStarted($user));

        return new TwoFactorSetup(
            secret: $secret,
            provisioningUri: $this->twoFactor->provisioningUri($secret, $label ?? $this->label($user)),
            recoveryCodes: $codes,
        );
    }

    private function label(TwoFactorAuthenticatable&Model $user): string
    {
        $email = $user->getAttribute('email');

        return is_string($email) && $email !== '' ? $email : (string) $user->getKey();
    }

    /**
     * @return array{secret: string, recovery_codes: string, confirmed_at: string, last_used_timestep: string}
     */
    private function columns(): array
    {
        /** @var array{secret: string, recovery_codes: string, confirmed_at: string, last_used_timestep: string} $columns */
        $columns = config('two-factor.columns');

        return $columns;
    }
}
