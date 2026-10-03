<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;
use RoundlyConsulting\TwoFactor\Events\TwoFactorDisabled;
use RoundlyConsulting\TwoFactor\Support\ConfigGuard;

/**
 * Clears every two-factor column, fully disabling 2FA for the user.
 */
final readonly class DisableTwoFactor
{
    public function __construct(
        private ?Dispatcher $events = null,
    ) {}

    public function execute(TwoFactorAuthenticatable&Model $user): void
    {
        foreach (ConfigGuard::columns() as $column) {
            $user->setAttribute($column, null);
        }

        $user->save();

        $this->events?->dispatch(new TwoFactorDisabled($user));
    }
}
