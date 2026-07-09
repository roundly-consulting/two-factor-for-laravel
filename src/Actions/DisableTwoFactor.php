<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;
use RoundlyConsulting\TwoFactor\Events\TwoFactorDisabled;

/**
 * Clears every two-factor column, fully disabling 2FA for the user.
 */
final class DisableTwoFactor
{
    public function __construct(
        private readonly ?Dispatcher $events = null,
    ) {}

    public function execute(TwoFactorAuthenticatable&Model $user): void
    {
        /** @var array{secret: string, recovery_codes: string, confirmed_at: string, last_used_timestep: string} $columns */
        $columns = config('two-factor.columns');

        foreach ($columns as $column) {
            $user->setAttribute($column, null);
        }

        $user->save();

        $this->events?->dispatch(new TwoFactorDisabled($user));
    }
}
