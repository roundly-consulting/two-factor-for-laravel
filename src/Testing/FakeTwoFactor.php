<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Testing;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorService;
use RoundlyConsulting\TwoFactor\DataTransferObjects\VerificationResult;
use RoundlyConsulting\TwoFactor\Enums\TwoFactorMethod;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorAssertionFailedException;
use SensitiveParameter;

/**
 * A first-class, no-crypto testing double for {@see TwoFactorService}, swapped in
 * by TwoFactor::fake(). It performs NO TOTP math — outcomes are programmable
 * (accept/acceptRecoveryCode/reject/replay/acceptCode) and every attempt()/verifyFor()
 * call is recorded so a host can assert its 2FA flow without freezing the clock or
 * threading real secrets.
 *
 * Test-only: it lives in runtime autoload purely to follow Laravel's own Fakes
 * pattern, is bound solely via TwoFactor::fake(), and must never reach production.
 * Assertions throw a package exception (not a PHPUnit assertion) so it works under
 * any runner.
 *
 * ```php
 * $fake = TwoFactor::fake()->accept();
 * $this->post('/login/2fa', ['code' => '123456'])->assertOk();
 * $fake->assertVerifiedFor($user);
 *
 * TwoFactor::fake()->acceptRecoveryCode()->withRemainingRecoveryCodes(2);
 * $fake->assertVerifiedVia(TwoFactorMethod::RecoveryCode);
 * ```
 */
final class FakeTwoFactor implements TwoFactorService
{
    private const CANNED_SECRET = 'FAKESECRET234567';

    private const CANNED_CODE = '123456';

    private bool $accepts = true;

    private ?string $onlyCode = null;

    private TwoFactorMethod $method = TwoFactorMethod::Totp;

    private bool $replays = false;

    private ?int $remainingRecoveryCodes = null;

    private ?string $secret = null;

    /** @var list<string>|null */
    private ?array $recoveryCodes = null;

    /**
     * @var list<array{user: TwoFactorAuthenticatable&Model, code: string, verified: bool, method: TwoFactorMethod|null}>
     */
    private array $verifications = [];

    /** @var list<string> */
    private array $attemptedCodes = [];

    /**
     * Make every verify()/attempt()/verifyFor() succeed via TOTP (the default).
     */
    public function accept(): self
    {
        return $this->succeedVia(TwoFactorMethod::Totp);
    }

    /**
     * Make every attempt()/verifyFor() succeed as if a recovery code was spent.
     */
    public function acceptRecoveryCode(): self
    {
        return $this->succeedVia(TwoFactorMethod::RecoveryCode);
    }

    /**
     * Make every verify()/attempt()/verifyFor() fail.
     */
    public function reject(): self
    {
        $this->accepts = false;
        $this->onlyCode = null;
        $this->replays = false;

        return $this;
    }

    /**
     * Make every attempt() fail as a replay — a valid code whose timestep was
     * already claimed (`replayed: true`).
     */
    public function replay(): self
    {
        $this->reject();
        $this->replays = true;

        return $this;
    }

    /**
     * Accept only this exact code (via the current method); every other code fails.
     */
    public function acceptCode(#[SensitiveParameter] string $code): self
    {
        $this->onlyCode = $code;
        $this->replays = false;

        return $this;
    }

    /**
     * Pin the remaining recovery-code count attempt() reports. Unset, the fake
     * reports the user's stored count, one lower when a recovery code passes.
     */
    public function withRemainingRecoveryCodes(int $remaining): self
    {
        $this->remainingRecoveryCodes = max(0, $remaining);

        return $this;
    }

    public function withSecret(#[SensitiveParameter] string $secret): self
    {
        $this->secret = $secret;

        return $this;
    }

    public function withRecoveryCodes(#[SensitiveParameter] string ...$codes): self
    {
        $this->recoveryCodes = array_values($codes);

        return $this;
    }

    public function generateSecret(?int $length = null): string
    {
        if ($this->secret !== null) {
            return $this->secret;
        }

        $length ??= 16;

        if ($length <= 0) {
            return '';
        }

        return substr(str_repeat(self::CANNED_SECRET, (int) ceil($length / strlen(self::CANNED_SECRET))), 0, $length);
    }

    public function currentCode(#[SensitiveParameter] string $secret, ?int $timestamp = null): string
    {
        return self::CANNED_CODE;
    }

    public function verify(
        #[SensitiveParameter] string $secret,
        #[SensitiveParameter] string $code,
        ?int $window = null,
    ): int|false {
        $this->attemptedCodes[] = $code;

        return $this->passes($code) ? 0 : false;
    }

    public function attempt(TwoFactorAuthenticatable&Model $user, #[SensitiveParameter] string $code): VerificationResult
    {
        $this->attemptedCodes[] = $code;

        $result = $this->outcome($user, $code);

        $this->verifications[] = [
            'user' => $user,
            'code' => $code,
            'verified' => $result->verified,
            'method' => $result->method,
        ];

        return $result;
    }

    public function verifyFor(TwoFactorAuthenticatable&Model $user, #[SensitiveParameter] string $code): bool
    {
        return $this->attempt($user, $code)->verified;
    }

    public function provisioningUri(
        #[SensitiveParameter] string $secret,
        string $label,
        ?string $issuer = null,
    ): string {
        $issuer ??= 'Fake';

        return sprintf(
            'otpauth://totp/%s:%s?secret=%s&issuer=%s',
            rawurlencode($issuer),
            rawurlencode($label),
            $secret,
            rawurlencode($issuer),
        );
    }

    /**
     * @return list<string>
     */
    public function generateRecoveryCodes(?int $count = null): array
    {
        if ($this->recoveryCodes !== null) {
            return $this->recoveryCodes;
        }

        // range(1, 0) counts *down* — it yields [1, 0], so a zero or negative
        // count has to short-circuit or the fake hands back codes nobody asked
        // for (the real service returns an empty list).
        $count = max(0, $count ?? 8);

        if ($count === 0) {
            return [];
        }

        return array_map(
            static fn (int $i): string => sprintf('FAKE-%04d-%04d', $i, $i),
            range(1, $count),
        );
    }

    public function assertVerified(): void
    {
        foreach ($this->verifications as $verification) {
            if ($verification['verified']) {
                return;
            }
        }

        throw new TwoFactorAssertionFailedException(
            'Expected at least one successful verification, but none succeeded.',
        );
    }

    public function assertVerifiedFor(TwoFactorAuthenticatable&Model $user): void
    {
        foreach ($this->verifications as $verification) {
            if ($verification['verified'] && $verification['user']->is($user)) {
                return;
            }
        }

        throw new TwoFactorAssertionFailedException(
            'Expected a successful verification for the given user, but none was recorded.',
        );
    }

    public function assertVerifiedVia(TwoFactorMethod $method): void
    {
        foreach ($this->verifications as $verification) {
            if ($verification['verified'] && $verification['method'] === $method) {
                return;
            }
        }

        throw new TwoFactorAssertionFailedException(
            "Expected a successful verification via [{$method->value}], but none was recorded.",
        );
    }

    public function assertVerificationFailed(): void
    {
        foreach ($this->verifications as $verification) {
            if (! $verification['verified']) {
                return;
            }
        }

        throw new TwoFactorAssertionFailedException(
            'Expected at least one failed verification, but none failed.',
        );
    }

    public function assertNothingVerified(): void
    {
        if ($this->verifications !== []) {
            $count = count($this->verifications);

            throw new TwoFactorAssertionFailedException(
                "Expected no verifications, but {$count} were recorded.",
            );
        }
    }

    public function assertVerifyCount(int $count): void
    {
        $actual = count($this->verifications);

        if ($actual !== $count) {
            throw new TwoFactorAssertionFailedException(
                "Expected {$count} verification(s), but {$actual} were recorded.",
            );
        }
    }

    public function assertCodeAttempted(#[SensitiveParameter] string $code): void
    {
        if (! in_array($code, $this->attemptedCodes, true)) {
            throw new TwoFactorAssertionFailedException(
                'Expected the given code to have been attempted, but it was not.',
            );
        }
    }

    private function succeedVia(TwoFactorMethod $method): self
    {
        $this->accepts = true;
        $this->onlyCode = null;
        $this->replays = false;
        $this->method = $method;

        return $this;
    }

    private function outcome(TwoFactorAuthenticatable $user, #[SensitiveParameter] string $code): VerificationResult
    {
        $stored = count($user->twoFactorRecoveryCodes());

        if ($this->replays) {
            return VerificationResult::failed($this->remainingRecoveryCodes ?? $stored, replayed: true);
        }

        if (! $this->passes($code)) {
            return VerificationResult::failed($this->remainingRecoveryCodes ?? $stored);
        }

        $spent = $this->method === TwoFactorMethod::RecoveryCode ? 1 : 0;

        return VerificationResult::via($this->method, $this->remainingRecoveryCodes ?? max(0, $stored - $spent));
    }

    private function passes(#[SensitiveParameter] string $code): bool
    {
        if ($this->onlyCode !== null) {
            return ConstantTime::equals($this->onlyCode, $code);
        }

        return $this->accepts;
    }
}
