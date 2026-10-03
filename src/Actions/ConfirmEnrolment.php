<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Date;
use RoundlyConsulting\TwoFactor\Contracts\ReplayGuard;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorService;
use RoundlyConsulting\TwoFactor\Events\TwoFactorConfirmed;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorCodeException;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorNotPendingException;
use RoundlyConsulting\TwoFactor\Support\ConfigGuard;
use SensitiveParameter;

/**
 * Confirms a pending enrolment by verifying the first code, stamping
 * confirmed_at. Only a pending enrolment can be confirmed: an already-enabled
 * user is refused with TwoFactorNotPendingException before the code is looked
 * at, so a clean return always means "this code just enabled two-factor".
 */
final readonly class ConfirmEnrolment
{
    public function __construct(
        private TwoFactorService $twoFactor,
        private ReplayGuard $replayGuard,
        private ?Dispatcher $events = null,
    ) {}

    /**
     * @throws TwoFactorNotPendingException when nothing is pending — including when
     *                                      two-factor is already enabled
     * @throws InvalidTwoFactorCodeException
     */
    public function execute(TwoFactorAuthenticatable&Model $user, #[SensitiveParameter] string $code): void
    {
        // Never a silent success: returning here without checking the code let any
        // caller that treats a clean return as proof of possession accept any code.
        if ($user->hasTwoFactorEnabled()) {
            throw TwoFactorNotPendingException::alreadyEnabled();
        }

        if (! $user->hasPendingTwoFactor()) {
            throw TwoFactorNotPendingException::make();
        }

        $secret = (string) $user->twoFactorSecret();

        $timestep = $this->twoFactor->verify($secret, $code);

        if ($timestep === false) {
            throw InvalidTwoFactorCodeException::make();
        }

        $user->setAttribute(ConfigGuard::columns()['confirmed_at'], Date::now());
        $user->save();

        // Spend the confirming timestep so the exact code just typed cannot be
        // replayed once at the first login (security hardening — no crypto change).
        $this->replayGuard->claim($user, $timestep);

        $this->events?->dispatch(new TwoFactorConfirmed($user));
    }
}
