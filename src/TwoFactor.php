<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\ReplayGuard;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorService;
use RoundlyConsulting\TwoFactor\Enums\HashAlgorithm;
use RoundlyConsulting\TwoFactor\Enums\RecoveryCodeStorage;
use RoundlyConsulting\TwoFactor\Events\RecoveryCodeConsumed;
use RoundlyConsulting\TwoFactor\Events\TwoFactorReplayDetected;
use RoundlyConsulting\TwoFactor\Events\TwoFactorVerificationFailed;
use RoundlyConsulting\TwoFactor\Events\TwoFactorVerified;
use RoundlyConsulting\TwoFactor\Support\Base32;
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
        $length ??= (int) config('two-factor.secret_length', 16);

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
        $window ??= (int) config('two-factor.window', 1);

        return $this->totp()->verify($secret, $code, $window);
    }

    /**
     * Verify a code for a user: TOTP with replay protection, then a single-use
     * recovery-code fallback. Returns whether the code was accepted.
     */
    public function verifyFor(TwoFactorAuthenticatable&Model $user, #[SensitiveParameter] string $code): bool
    {
        $secret = $user->twoFactorSecret();

        if ($secret === null) {
            return false;
        }

        $timestep = $this->verify($secret, $code);

        if ($timestep !== false) {
            if ($this->replayGuard->reject($user, $timestep)) {
                $this->events?->dispatch(new TwoFactorReplayDetected($user, $timestep));

                return false;
            }

            $this->replayGuard->record($user, $timestep);

            $this->events?->dispatch(new TwoFactorVerified($user, viaRecoveryCode: false));

            return true;
        }

        if ($this->consumeRecoveryCode($user, $code)) {
            $this->events?->dispatch(new TwoFactorVerified($user, viaRecoveryCode: true));

            return true;
        }

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
            'digits' => (int) config('two-factor.digits', 6),
            'period' => (int) config('two-factor.period', 30),
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
        $remaining = $manager->consume($user->twoFactorRecoveryCodes(), $code);

        if ($remaining === null) {
            return false;
        }

        $user->setAttribute((string) config('two-factor.columns.recovery_codes'), $remaining);
        $user->save();

        $this->events?->dispatch(new RecoveryCodeConsumed($user));

        return true;
    }

    private function totp(): Totp
    {
        return new Totp(
            $this->algorithm(),
            (int) config('two-factor.digits', 6),
            (int) config('two-factor.period', 30),
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
