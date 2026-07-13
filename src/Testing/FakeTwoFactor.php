<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Testing;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorService;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorAssertionFailedException;
use SensitiveParameter;

/**
 * A first-class, no-crypto testing double for {@see TwoFactorService}, swapped in
 * by TwoFactor::fake(). It performs NO TOTP math — outcomes are programmable
 * (accept/reject/acceptCode) and every verifyFor() call is recorded so a host can
 * assert its 2FA flow without freezing the clock or threading real secrets.
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
 * ```
 */
final class FakeTwoFactor implements TwoFactorService
{
    private const CANNED_SECRET = 'FAKESECRET234567';

    private const CANNED_CODE = '123456';

    private bool $accepts = true;

    private ?string $onlyCode = null;

    private ?string $secret = null;

    /** @var list<string>|null */
    private ?array $recoveryCodes = null;

    /**
     * @var list<array{user: TwoFactorAuthenticatable&Model, code: string, verified: bool}>
     */
    private array $verifications = [];

    /** @var list<string> */
    private array $attemptedCodes = [];

    /**
     * Make every verify()/verifyFor() succeed (the default).
     */
    public function accept(): self
    {
        $this->accepts = true;
        $this->onlyCode = null;

        return $this;
    }

    /**
     * Make every verify()/verifyFor() fail.
     */
    public function reject(): self
    {
        $this->accepts = false;
        $this->onlyCode = null;

        return $this;
    }

    /**
     * Accept only this exact code; every other code fails.
     */
    public function acceptCode(#[SensitiveParameter] string $code): self
    {
        $this->onlyCode = $code;

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

    public function verifyFor(TwoFactorAuthenticatable&Model $user, #[SensitiveParameter] string $code): bool
    {
        $this->attemptedCodes[] = $code;

        $verified = $this->passes($code);

        $this->verifications[] = ['user' => $user, 'code' => $code, 'verified' => $verified];

        return $verified;
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

        $count ??= 8;

        return array_map(
            static fn (int $i): string => sprintf('FAKE-%04d-%04d', $i, $i),
            range(1, max(0, $count)),
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

    private function passes(#[SensitiveParameter] string $code): bool
    {
        if ($this->onlyCode !== null) {
            return ConstantTime::equals($this->onlyCode, $code);
        }

        return $this->accepts;
    }
}
