<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\RateLimiter;
use RoundlyConsulting\TwoFactor\Contracts\ReplayGuard;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorService;
use RoundlyConsulting\TwoFactor\DataTransferObjects\AttemptLimit;
use RoundlyConsulting\TwoFactor\DataTransferObjects\VerificationResult;
use RoundlyConsulting\TwoFactor\Enums\RecoveryCodeStorage;
use RoundlyConsulting\TwoFactor\Enums\TwoFactorMethod;
use RoundlyConsulting\TwoFactor\Events\RecoveryCodeConsumed;
use RoundlyConsulting\TwoFactor\Events\TwoFactorRateLimited;
use RoundlyConsulting\TwoFactor\Events\TwoFactorReplayDetected;
use RoundlyConsulting\TwoFactor\Events\TwoFactorVerificationFailed;
use RoundlyConsulting\TwoFactor\Events\TwoFactorVerified;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorRateLimitedException;
use RoundlyConsulting\TwoFactor\Support\ConfigGuard;
use RoundlyConsulting\TwoFactor\Support\RecoveryCodeManager;
use SensitiveParameter;

/**
 * Attempts a login-challenge code for a user: TOTP with replay protection, then
 * a single-use recovery-code fallback, all behind the per-user brute-force
 * limiter. Reports which factor passed and how many recovery codes remain, so a
 * caller never has to listen to its own call.
 */
final readonly class AttemptTwoFactorCode
{
    public function __construct(
        private TwoFactorService $twoFactor,
        private ReplayGuard $replayGuard,
        private ?Dispatcher $events = null,
    ) {}

    /**
     * @throws TwoFactorRateLimitedException when the per-user limiter is exhausted
     */
    public function execute(TwoFactorAuthenticatable&Model $user, #[SensitiveParameter] string $code): VerificationResult
    {
        // Only a fully confirmed enrolment can satisfy a login challenge; a
        // secret that was persisted but never confirmed is not a working second
        // factor (finding 7).
        if (! $user->hasTwoFactorEnabled()) {
            return VerificationResult::failed($this->remaining($user));
        }

        $secret = $user->twoFactorSecret();

        if ($secret === null) {
            return VerificationResult::failed($this->remaining($user));
        }

        $limit = ConfigGuard::attemptLimit();
        $key = $this->rateLimiterKey($user);

        $this->countAttempt($user, $limit, $key);

        $timestep = $this->twoFactor->verify($secret, $code);

        if ($timestep !== false) {
            // A replay stays counted, like any other failure.
            if (! $this->replayGuard->claim($user, $timestep)) {
                $this->events?->dispatch(new TwoFactorReplayDetected($user, $timestep));

                return VerificationResult::failed($this->remaining($user), replayed: true);
            }

            $this->clearAttempts($limit, $key);
            $this->events?->dispatch(new TwoFactorVerified($user, TwoFactorMethod::Totp));

            return VerificationResult::via(TwoFactorMethod::Totp, $this->remaining($user));
        }

        $result = $this->consumeRecoveryCode($user, $code);

        if ($result->verified) {
            $this->clearAttempts($limit, $key);
            $this->events?->dispatch(new TwoFactorVerified($user, TwoFactorMethod::RecoveryCode));

            return $result;
        }

        $this->events?->dispatch(new TwoFactorVerificationFailed($user));

        return $result;
    }

    /**
     * The recovery-code fallback. The remaining count comes from the row read
     * under the lock, so it is the true count even when the caller's instance
     * is stale.
     */
    private function consumeRecoveryCode(TwoFactorAuthenticatable&Model $user, #[SensitiveParameter] string $code): VerificationResult
    {
        $manager = new RecoveryCodeManager(
            RecoveryCodeStorage::fromConfig((string) config('two-factor.recovery_codes.storage')),
        );
        $column = (string) config('two-factor.columns.recovery_codes');

        // Consume under a transaction with a locked, fresh re-read of the row so
        // two concurrent requests carrying the same code cannot both match a
        // stale in-memory list and double-spend it (finding 1). The write is
        // scoped to the freshly-loaded row, never the host's own instance, so no
        // unrelated dirty attribute is flushed (finding 11).
        $result = $user->getConnection()->transaction(function () use ($user, $code, $manager, $column): VerificationResult {
            /** @var (TwoFactorAuthenticatable&Model)|null $locked */
            $locked = $user->newQuery()->lockForUpdate()->find($user->getKey());

            if ($locked === null) {
                return VerificationResult::failed(0);
            }

            $current = $locked->twoFactorRecoveryCodes();
            $remaining = $manager->consume($current, $code);

            if ($remaining === null) {
                return VerificationResult::failed(count($current));
            }

            $locked->timestamps = false;
            $locked->setAttribute($column, $remaining);
            $locked->save();

            // Reflect the consumption on the caller's instance for read-back.
            $user->setAttribute($column, $remaining);
            $user->syncOriginalAttribute($column);

            return VerificationResult::via(TwoFactorMethod::RecoveryCode, count($remaining));
        });

        if ($result->verified) {
            $this->events?->dispatch(new RecoveryCodeConsumed($user, $result->remainingRecoveryCodes));
        }

        return $result;
    }

    private function remaining(TwoFactorAuthenticatable $user): int
    {
        return count($user->twoFactorRecoveryCodes());
    }

    /**
     * Count this attempt BEFORE any verification work, as one atomic increment,
     * and refuse it when the count passes `attempts.max`. Reading the count and
     * recording the failure afterwards let every request of a parallel burst pass
     * the read before any failure landed — N guesses in flight were N
     * verifications. The count stands unless the code passes (see clearAttempts).
     *
     * @throws TwoFactorRateLimitedException
     */
    private function countAttempt(TwoFactorAuthenticatable&Model $user, ?AttemptLimit $limit, string $key): void
    {
        if ($limit === null) {
            return;
        }

        $attempts = RateLimiter::hit($key, $limit->decay);

        if ($attempts <= $limit->max) {
            return;
        }

        $seconds = RateLimiter::availableIn($key);

        $this->events?->dispatch(new TwoFactorRateLimited($user, $seconds));

        throw TwoFactorRateLimitedException::make($seconds);
    }

    private function clearAttempts(?AttemptLimit $limit, string $key): void
    {
        if ($limit !== null) {
            RateLimiter::clear($key);
        }
    }

    private function rateLimiterKey(TwoFactorAuthenticatable&Model $user): string
    {
        return 'two-factor:'.$user::class.':'.$user->getKey();
    }
}
