<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\RateLimiter;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\Otp\InvalidOtpParameterException;
use RoundlyConsulting\Crypto\Otp\ProvisioningUri;
use RoundlyConsulting\Crypto\Otp\Totp;
use RoundlyConsulting\Crypto\Random\Secret;
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
use RoundlyConsulting\TwoFactor\Exceptions\InvalidBase32Exception;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidTwoFactorConfigException;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorRateLimitedException;
use RoundlyConsulting\TwoFactor\Support\ConfigGuard;
use RoundlyConsulting\TwoFactor\Support\RecoveryCodeManager;
use SensitiveParameter;

/**
 * The package's public entry point: TOTP primitives plus the replay-safe,
 * recovery-aware attempt()/verifyFor() used during a login challenge.
 *
 * The OTP maths, the base32 codec and the CSPRNG all come from
 * crypto-for-laravel. This class is the boundary: it builds those primitives
 * from this package's own config and translates every crypto failure back into
 * the two-factor exception a host already catches.
 */
final class TwoFactor implements TwoFactorService
{
    public function __construct(
        private readonly ReplayGuard $replayGuard,
        private readonly ?Dispatcher $events = null,
    ) {}

    /**
     * A fresh base32 secret backed by the CSPRNG.
     *
     * @throws InvalidTwoFactorConfigException when the length is out of range
     */
    public function generateSecret(?int $length = null): string
    {
        $length ??= ConfigGuard::secretLength();

        // Bound an explicit caller length by the same rule as the configured one,
        // so no path can mint a secret below the package's entropy floor.
        return Secret::base32(ConfigGuard::assertSecretLength($length));
    }

    /**
     * @throws InvalidBase32Exception when the secret is not valid base32
     */
    public function currentCode(#[SensitiveParameter] string $secret, ?int $timestamp = null): string
    {
        try {
            return $this->totp()->codeAt($secret, $timestamp);
        } catch (InvalidEncodingException $e) {
            throw InvalidBase32Exception::fromCodec($e);
        }
    }

    /**
     * @return int|false the matched timestep, or false
     *
     * @throws InvalidBase32Exception when the secret is not valid base32
     * @throws InvalidTwoFactorConfigException when the window is out of range
     */
    public function verify(
        #[SensitiveParameter] string $secret,
        #[SensitiveParameter] string $code,
        ?int $window = null,
    ): int|false {
        $window ??= ConfigGuard::window();

        try {
            return $this->totp()->verify($secret, $code, $window);
        } catch (InvalidEncodingException $e) {
            throw InvalidBase32Exception::fromCodec($e);
        } catch (InvalidOtpParameterException) {
            // The only parameter the caller can still push out of range here is
            // the explicit window; digits/period came through ConfigGuard.
            throw InvalidTwoFactorConfigException::window($window);
        }
    }

    /**
     * Attempt a code for a user: TOTP with replay protection, then a single-use
     * recovery-code fallback. Reports which factor passed and how many recovery
     * codes remain, so a caller never has to listen to its own call.
     *
     * @throws TwoFactorRateLimitedException when the per-user limiter is exhausted
     */
    public function attempt(TwoFactorAuthenticatable&Model $user, #[SensitiveParameter] string $code): VerificationResult
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

        if ($limit !== null && RateLimiter::tooManyAttempts($key, $limit->max)) {
            $seconds = RateLimiter::availableIn($key);
            $this->events?->dispatch(new TwoFactorRateLimited($user, $seconds));

            throw TwoFactorRateLimitedException::make($seconds);
        }

        $timestep = $this->verify($secret, $code);

        if ($timestep !== false) {
            if (! $this->replayGuard->claim($user, $timestep)) {
                $this->registerFailure($limit, $key);
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

        $this->registerFailure($limit, $key);
        $this->events?->dispatch(new TwoFactorVerificationFailed($user));

        return $result;
    }

    /**
     * Verify a code for a user — {@see attempt()} reduced to whether it passed.
     *
     * @throws TwoFactorRateLimitedException when the per-user limiter is exhausted
     */
    public function verifyFor(TwoFactorAuthenticatable&Model $user, #[SensitiveParameter] string $code): bool
    {
        return $this->attempt($user, $code)->verified;
    }

    public function provisioningUri(
        #[SensitiveParameter] string $secret,
        string $label,
        ?string $issuer = null,
    ): string {
        return ProvisioningUri::totp(
            $secret,
            $label,
            $issuer ?? ConfigGuard::issuer(),
            ConfigGuard::algorithm(),
            ConfigGuard::digits(),
            ConfigGuard::period(),
        );
    }

    /**
     * @return list<string>
     */
    public function generateRecoveryCodes(?int $count = null): array
    {
        $count ??= (int) config('two-factor.recovery_codes.count', 8);

        return $this->recoveryCodes()->generate($count);
    }

    /**
     * The recovery-code fallback. The remaining count comes from the row read
     * under the lock, so it is the true count even when the caller's instance
     * is stale.
     */
    private function consumeRecoveryCode(TwoFactorAuthenticatable&Model $user, #[SensitiveParameter] string $code): VerificationResult
    {
        $manager = $this->recoveryCodes();
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

    private function registerFailure(?AttemptLimit $limit, string $key): void
    {
        if ($limit !== null) {
            RateLimiter::hit($key, $limit->decay);
        }
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

    /**
     * The OTP primitive, parameterised from this package's own config. Crypto is
     * zero-config: every knob is passed in here, bounds-checked first.
     */
    private function totp(): Totp
    {
        return new Totp(
            ConfigGuard::algorithm(),
            ConfigGuard::digits(),
            ConfigGuard::period(),
        );
    }

    private function recoveryCodes(): RecoveryCodeManager
    {
        return new RecoveryCodeManager(
            RecoveryCodeStorage::fromConfig((string) config('two-factor.recovery_codes.storage')),
        );
    }
}
