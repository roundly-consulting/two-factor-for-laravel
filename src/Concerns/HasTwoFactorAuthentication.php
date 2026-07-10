<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Concerns;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Actions\ConfirmEnrolment;
use RoundlyConsulting\TwoFactor\Actions\DisableTwoFactor;
use RoundlyConsulting\TwoFactor\Actions\RegenerateRecoveryCodes;
use RoundlyConsulting\TwoFactor\Actions\StartEnrolment;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorService;
use RoundlyConsulting\TwoFactor\DataTransferObjects\TwoFactorSetup;
use RoundlyConsulting\TwoFactor\Enums\RecoveryCodeStorage;
use SensitiveParameter;

/**
 * Gives a host user model the two-factor state helpers required by
 * TwoFactorAuthenticatable. Spread twoFactorCasts() into the model's casts():
 *
 * ```php
 * protected function casts(): array
 * {
 *     return [...$this->twoFactorCasts()];
 * }
 * ```
 *
 * Column names are always read through config('two-factor.columns') so a host
 * with a remapped schema stays in control.
 *
 * @phpstan-require-extends Model
 *
 * @phpstan-require-implements TwoFactorAuthenticatable
 */
trait HasTwoFactorAuthentication
{
    /**
     * Hide the sensitive two-factor columns from array/JSON serialization so a
     * host that returns the user model (e.g. `return $user;` from a route) never
     * leaks the decrypted TOTP secret, the recovery codes, or the replay marker.
     * Laravel merges trait initializers automatically at model boot.
     */
    public function initializeHasTwoFactorAuthentication(): void
    {
        $columns = $this->twoFactorColumnMap();

        $this->makeHidden([
            $columns['secret'],
            $columns['recovery_codes'],
            $columns['last_used_timestep'],
        ]);
    }

    /**
     * Begin (or restart) a pending enrolment for this user.
     */
    public function startTwoFactorEnrolment(?string $label = null): TwoFactorSetup
    {
        return app(StartEnrolment::class)->execute($this, $label);
    }

    /**
     * Confirm the pending enrolment with the first authenticator code.
     */
    public function confirmTwoFactor(#[SensitiveParameter] string $code): void
    {
        app(ConfirmEnrolment::class)->execute($this, $code);
    }

    /**
     * Verify a login-challenge code (TOTP with replay protection, then a
     * single-use recovery-code fallback).
     */
    public function verifyTwoFactorCode(#[SensitiveParameter] string $code): bool
    {
        return app(TwoFactorService::class)->verifyFor($this, $code);
    }

    /**
     * Fully disable two-factor authentication for this user.
     */
    public function disableTwoFactor(): void
    {
        app(DisableTwoFactor::class)->execute($this);
    }

    /**
     * Replace this user's recovery codes, returning the new plaintext set once.
     *
     * @return list<string>
     */
    public function regenerateTwoFactorRecoveryCodes(): array
    {
        return app(RegenerateRecoveryCodes::class)->execute($this);
    }

    /**
     * How many single-use recovery codes remain.
     */
    public function twoFactorRecoveryCodesRemaining(): int
    {
        return count($this->twoFactorRecoveryCodes());
    }

    /**
     * The label rendered in the provisioning URI. Override to key on username,
     * phone, or any other attribute instead of the default email → primary key.
     */
    public function twoFactorLabel(): string
    {
        $email = $this->getAttribute('email');

        return is_string($email) && $email !== '' ? $email : (string) $this->getKey();
    }

    /**
     * @return array<string, string>
     */
    public function twoFactorCasts(): array
    {
        $columns = $this->twoFactorColumnMap();

        return [
            $columns['secret'] => 'encrypted',
            $columns['recovery_codes'] => RecoveryCodeStorage::fromConfig(
                (string) config('two-factor.recovery_codes.storage'),
            )->cast(),
            $columns['confirmed_at'] => 'datetime',
        ];
    }

    public function hasTwoFactorEnabled(): bool
    {
        return $this->twoFactorSecret() !== null
            && $this->getAttribute($this->twoFactorColumnMap()['confirmed_at']) !== null;
    }

    public function hasPendingTwoFactor(): bool
    {
        return $this->twoFactorSecret() !== null
            && $this->getAttribute($this->twoFactorColumnMap()['confirmed_at']) === null;
    }

    public function twoFactorSecret(): ?string
    {
        $secret = $this->getAttribute($this->twoFactorColumnMap()['secret']);

        return $secret === null ? null : (string) $secret;
    }

    /**
     * @return list<string>
     */
    public function twoFactorRecoveryCodes(): array
    {
        $codes = $this->getAttribute($this->twoFactorColumnMap()['recovery_codes']);

        if (! is_array($codes)) {
            return [];
        }

        return array_values(array_map(strval(...), $codes));
    }

    /**
     * @return array{secret: string, recovery_codes: string, confirmed_at: string, last_used_timestep: string}
     */
    protected function twoFactorColumnMap(): array
    {
        /** @var array{secret: string, recovery_codes: string, confirmed_at: string, last_used_timestep: string} $columns */
        $columns = config('two-factor.columns');

        return $columns;
    }
}
