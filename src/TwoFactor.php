<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\RateLimiter;
use RoundlyConsulting\TwoFactor\Contracts\ReplayGuard;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorService;
use RoundlyConsulting\TwoFactor\DataTransferObjects\AttemptLimit;
use RoundlyConsulting\TwoFactor\Enums\HashAlgorithm;
use RoundlyConsulting\TwoFactor\Enums\RecoveryCodeStorage;
use RoundlyConsulting\TwoFactor\Events\RecoveryCodeConsumed;
use RoundlyConsulting\TwoFactor\Events\TwoFactorRateLimited;
use RoundlyConsulting\TwoFactor\Events\TwoFactorReplayDetected;
use RoundlyConsulting\TwoFactor\Events\TwoFactorVerificationFailed;
use RoundlyConsulting\TwoFactor\Events\TwoFactorVerified;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorRateLimitedException;
use RoundlyConsulting\TwoFactor\Support\Base32;
use RoundlyConsulting\TwoFactor\Support\ConfigGuard;
use RoundlyConsulting\TwoFactor\Support\RecoveryCodeManager;
use RoundlyConsulting\TwoFactor\Support\Totp;
use SensitiveParameter;

/**
 * The package's public entry point: TOTP primitives plus the replay-safe,
 * recovery-aware verifyFor() used during a login challenge.
 */
final class TwoFactor implements TwoFactorService
{
    public function __construct(
        private readonly ReplayGuard $replayGuard,
        private readonly ?Dispatcher $events = null,
    ) {}

    /**
     * A fresh base32 secret backed by random_bytes.
     */
    public function generateSecret(?int $length = null): string
    {
        $length ??= ConfigGuard::secretLength();

        // Each base32 char encodes 5 bits; over-generate raw bytes then trim so
        // the output is exactly $length characters over the RFC 4648 alphabet.
        $rawBytes = max(1, (int) ceil($length * 5 / 8) + 1);
        $bytes = random_bytes($rawBytes);

        return substr(Base32::encode($bytes), 0, max(0, $length));
    }

    public function currentCode(#[SensitiveParameter] string $secret, ?int $timestamp = null): string
    {
        return $this->totp()->codeAt($secret, $timestamp);
    }

    /**
     * @return int|false the matched timestep, or false
     */
    public function verify(
        #[SensitiveParameter] string $secret,
        #[SensitiveParameter] string $code,
        ?int $window = null,
    ): int|false {
        $window ??= ConfigGuard::window();

        return $this->totp()->verify($secret, $code, $window);
    }

    /**
     * Verify a code for a user: TOTP with replay protection, then a single-use
     * recovery-code fallback. Returns whether the code was accepted.
     */
    public function verifyFor(TwoFactorAuthenticatable&Model $user, #[SensitiveParameter] string $code): bool
    {
        // Only a fully confirmed enrolment can satisfy a login challenge; a
        // secret that was persisted but never confirmed is not a working second
        // factor (finding 7).
        if (! $user->hasTwoFactorEnabled()) {
            return false;
        }

        $secret = $user->twoFactorSecret();

        if ($secret === null) {
            return false;
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

                return false;
            }

            $this->clearAttempts($limit, $key);
            $this->events?->dispatch(new TwoFactorVerified($user, viaRecoveryCode: false));

            return true;
        }

        if ($this->consumeRecoveryCode($user, $code)) {
            $this->clearAttempts($limit, $key);
            $this->events?->dispatch(new TwoFactorVerified($user, viaRecoveryCode: true));

            return true;
        }

        $this->registerFailure($limit, $key);
        $this->events?->dispatch(new TwoFactorVerificationFailed($user));

        return false;
    }

    public function provisioningUri(
        #[SensitiveParameter] string $secret,
        string $label,
        ?string $issuer = null,
    ): string {
        $issuer ??= $this->issuer();
        $algorithm = strtoupper($this->algorithm()->value);

        $query = http_build_query([
            'secret' => $secret,
            'issuer' => $issuer,
            'algorithm' => $algorithm,
            'digits' => ConfigGuard::digits(),
            'period' => ConfigGuard::period(),
        ], '', '&', PHP_QUERY_RFC3986);

        return sprintf(
            'otpauth://totp/%s:%s?%s',
            rawurlencode($issuer),
            rawurlencode($label),
            $query,
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

    private function consumeRecoveryCode(TwoFactorAuthenticatable&Model $user, #[SensitiveParameter] string $code): bool
    {
        $manager = $this->recoveryCodes();
        $column = (string) config('two-factor.columns.recovery_codes');

        // Consume under a transaction with a locked, fresh re-read of the row so
        // two concurrent requests carrying the same code cannot both match a
        // stale in-memory list and double-spend it (finding 1). The write is
        // scoped to the freshly-loaded row, never the host's own instance, so no
        // unrelated dirty attribute is flushed (finding 11).
        $consumed = $user->getConnection()->transaction(function () use ($user, $code, $manager, $column): bool {
            /** @var (TwoFactorAuthenticatable&Model)|null $locked */
            $locked = $user->newQuery()->lockForUpdate()->find($user->getKey());

            if ($locked === null) {
                return false;
            }

            $remaining = $manager->consume($locked->twoFactorRecoveryCodes(), $code);

            if ($remaining === null) {
                return false;
            }

            $locked->timestamps = false;
            $locked->setAttribute($column, $remaining);
            $locked->save();

            // Reflect the consumption on the caller's instance for read-back.
            $user->setAttribute($column, $remaining);
            $user->syncOriginalAttribute($column);

            return true;
        });

        if (! $consumed) {
            return false;
        }

        $this->events?->dispatch(new RecoveryCodeConsumed($user));

        return true;
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

    private function totp(): Totp
    {
        return new Totp(
            $this->algorithm(),
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

    private function algorithm(): HashAlgorithm
    {
        return HashAlgorithm::fromConfig((string) config('two-factor.algorithm'));
    }

    private function issuer(): string
    {
        $issuer = config('two-factor.issuer') ?? config('app.name');

        return (string) $issuer;
    }
}
