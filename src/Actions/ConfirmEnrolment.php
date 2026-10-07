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
 *
 * The code is verified against the row locked inside a transaction, never the
 * caller's in-memory secret: a concurrent start() may have replaced the pending
 * secret since the caller's instance was loaded, and stamping confirmed_at next
 * to that one would enable a secret the user never scanned.
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

        $columns = ConfigGuard::columns();

        $timestep = $user->getConnection()->transaction(function () use ($user, $code, $columns): int {
            /** @var (TwoFactorAuthenticatable&Model)|null $locked */
            $locked = $user->newQuery()->lockForUpdate()->find($user->getKey());

            // Re-checked on the locked row: another request may have confirmed,
            // disabled or deleted it since the caller's instance was loaded.
            if ($locked?->hasTwoFactorEnabled() === true) {
                throw TwoFactorNotPendingException::alreadyEnabled();
            }

            if ($locked === null || ! $locked->hasPendingTwoFactor()) {
                throw TwoFactorNotPendingException::make();
            }

            $timestep = $this->twoFactor->verify((string) $locked->twoFactorSecret(), $code);

            if ($timestep === false) {
                throw InvalidTwoFactorCodeException::make();
            }

            $locked->setAttribute($columns['confirmed_at'], Date::now());
            $locked->save();

            $this->sync($user, $locked, $columns);

            return $timestep;
        });

        // Spend the confirming timestep so the exact code just typed cannot be
        // replayed once at the first login (security hardening — no crypto change).
        $this->replayGuard->claim($user, $timestep);

        $this->events?->dispatch(new TwoFactorConfirmed($user));
    }

    /**
     * Mirror the confirmed row's two-factor columns (and updated_at) onto the
     * caller's instance for read-back, clean, without touching any other
     * attribute the host has pending on it.
     *
     * @param  array{secret: string, recovery_codes: string, confirmed_at: string, last_used_timestep: string}  $columns
     */
    private function sync(Model $user, Model $locked, array $columns): void
    {
        $names = array_values($columns);

        if ($locked->usesTimestamps() && $locked->getUpdatedAtColumn() !== null) {
            $names[] = $locked->getUpdatedAtColumn();
        }

        // Only columns the row really has, so the caller never gains an attribute
        // a later save() would try to write to a column that does not exist.
        $confirmed = array_intersect_key($locked->getAttributes(), array_flip($names));

        $user->setRawAttributes([...$user->getAttributes(), ...$confirmed]);

        foreach (array_keys($confirmed) as $name) {
            $user->syncOriginalAttribute($name);
        }
    }
}
