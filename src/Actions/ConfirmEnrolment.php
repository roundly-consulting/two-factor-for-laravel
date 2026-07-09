<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Date;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorService;
use RoundlyConsulting\TwoFactor\Events\TwoFactorConfirmed;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorCodeException;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorNotPendingException;
use SensitiveParameter;

/**
 * Confirms a pending enrolment by verifying the first code, stamping
 * confirmed_at. Idempotent once already enabled.
 */
final class ConfirmEnrolment
{
    public function __construct(
        private readonly TwoFactorService $twoFactor,
        private readonly ?Dispatcher $events = null,
    ) {}

    /**
     * @throws TwoFactorNotPendingException
     * @throws InvalidTwoFactorCodeException
     */
    public function execute(TwoFactorAuthenticatable&Model $user, #[SensitiveParameter] string $code): void
    {
        if ($user->hasTwoFactorEnabled()) {
            return;
        }

        if (! $user->hasPendingTwoFactor()) {
            throw TwoFactorNotPendingException::make();
        }

        $secret = (string) $user->twoFactorSecret();

        if ($this->twoFactor->verify($secret, $code) === false) {
            throw InvalidTwoFactorCodeException::make();
        }

        $user->setAttribute((string) config('two-factor.columns.confirmed_at'), Date::now());
        $user->save();

        $this->events?->dispatch(new TwoFactorConfirmed($user));
    }
}
