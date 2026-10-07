<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Testing;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorService;
use RoundlyConsulting\TwoFactor\DataTransferObjects\VerificationResult;
use RoundlyConsulting\TwoFactor\Enums\TwoFactorMethod;
use RoundlyConsulting\TwoFactor\Events\RecoveryCodeConsumed;
use RoundlyConsulting\TwoFactor\Events\TwoFactorReplayDetected;
use RoundlyConsulting\TwoFactor\Events\TwoFactorVerificationFailed;
use RoundlyConsulting\TwoFactor\Events\TwoFactorVerified;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorAssertionFailedException;
use RoundlyConsulting\TwoFactor\Support\ConfigGuard;
use RoundlyConsulting\TwoFactor\UserTwoFactor;
use SensitiveParameter;

/**
 * A first-class, no-crypto testing double for {@see TwoFactorService}, swapped in
 * by TwoFactor::fake(). It performs NO TOTP math — outcomes are programmable
 * (accept/acceptRecoveryCode/reject/replay/acceptCode) and every
 * `for($user)->attempt()` is recorded so a host can assert its 2FA flow without
 * freezing the clock or threading real secrets. Like the real action, `attempt()`
 * fails a user without confirmed two-factor whatever outcome is programmed, fires
 * the same events (`TwoFactorVerified`, `RecoveryCodeConsumed`,
 * `TwoFactorVerificationFailed`, `TwoFactorReplayDetected` — the replay carries
 * timestep 0, the step the fake's `verify()` reports), and a recovery-code pass
 * spends one stored code (the first), so `status()` agrees with the result.
 *
 * Enrolment writes (`start`, `confirm`, `disable`, `recoveryCodes()->regenerate`)
 * run the real actions against the fake's canned secret, codes and programmable
 * `verify()`, and are recorded once they succeed — including calls made through
 * the `HasTwoFactorAuthentication` verbs, which route through `for($user)`.
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
 * $this->post('/two-factor/disable')->assertOk();
 * $fake->assertDisabled($user);
 * ```
 */
final class TwoFactorFake implements TwoFactorService
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

    /** @var list<Model> */
    private array $started = [];

    /** @var list<Model> */
    private array $confirmed = [];

    /** @var list<Model> */
    private array $disabled = [];

    /** @var list<Model> */
    private array $regenerated = [];

    public function __construct(
        private readonly Container $container,
    ) {}

    public function for(TwoFactorAuthenticatable&Model $user): UserTwoFactor
    {
        return new RecordingUserTwoFactor($this, $this->container, $user);
    }

    /**
     * Make every verify() and attempt() succeed via TOTP (the default). attempt()
     * still fails a user without confirmed two-factor, like the real action.
     */
    public function accept(): self
    {
        return $this->succeedVia(TwoFactorMethod::Totp);
    }

    /**
     * Make every attempt() succeed as if a recovery code was spent.
     */
    public function acceptRecoveryCode(): self
    {
        return $this->succeedVia(TwoFactorMethod::RecoveryCode);
    }

    /**
     * Make every verify() and attempt() fail.
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
     * reports the user's stored count, one lower when a recovery code passes (and
     * spends one stored code). A recovery pass spends a stored code either way.
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

    /**
     * The programmed outcome of `for($user)->attempt($code)`, recorded.
     *
     * @internal called by the recording handle
     */
    public function recordAttempt(TwoFactorAuthenticatable&Model $user, #[SensitiveParameter] string $code): VerificationResult
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

    /**
     * @internal called by the recording handle
     */
    public function recordStarted(Model $user): void
    {
        $this->started[] = $user;
    }

    /**
     * @internal called by the recording handle
     */
    public function recordConfirmed(Model $user): void
    {
        $this->confirmed[] = $user;
    }

    /**
     * @internal called by the recording handle
     */
    public function recordDisabled(Model $user): void
    {
        $this->disabled[] = $user;
    }

    /**
     * @internal called by the recording handle
     */
    public function recordRegenerated(Model $user): void
    {
        $this->regenerated[] = $user;
    }

    /**
     * An enrolment was started — for the given user, when one is passed.
     */
    public function assertStarted(?Model $user = null): void
    {
        $this->assertRecorded($this->started, $user, 'an enrolment start');
    }

    public function assertNothingStarted(): void
    {
        $this->assertNoneRecorded($this->started, 'enrolment start');
    }

    /**
     * An enrolment was confirmed — for the given user, when one is passed.
     */
    public function assertConfirmed(?Model $user = null): void
    {
        $this->assertRecorded($this->confirmed, $user, 'a confirmed enrolment');
    }

    public function assertNothingConfirmed(): void
    {
        $this->assertNoneRecorded($this->confirmed, 'confirmation');
    }

    /**
     * Two-factor was disabled — for the given user, when one is passed.
     */
    public function assertDisabled(?Model $user = null): void
    {
        $this->assertRecorded($this->disabled, $user, 'two-factor to be disabled');
    }

    public function assertNothingDisabled(): void
    {
        $this->assertNoneRecorded($this->disabled, 'disable');
    }

    /**
     * Recovery codes were regenerated — for the given user, when one is passed.
     */
    public function assertRegenerated(?Model $user = null): void
    {
        $this->assertRecorded($this->regenerated, $user, 'recovery codes to be regenerated');
    }

    public function assertNothingRegenerated(): void
    {
        $this->assertNoneRecorded($this->regenerated, 'recovery-code regeneration');
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

    /**
     * @param  list<Model>  $recorded
     */
    private function assertRecorded(array $recorded, ?Model $user, string $what): void
    {
        foreach ($recorded as $candidate) {
            if ($user === null || $candidate->is($user)) {
                return;
            }
        }

        $for = $user === null ? '' : ' for the given user';

        throw new TwoFactorAssertionFailedException("Expected {$what}{$for}, but none was recorded.");
    }

    /**
     * @param  list<Model>  $recorded
     */
    private function assertNoneRecorded(array $recorded, string $what): void
    {
        if ($recorded !== []) {
            $count = count($recorded);

            throw new TwoFactorAssertionFailedException("Expected no {$what}, but {$count} were recorded.");
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

    /**
     * The programmed outcome, with the real action's side effects: its events and,
     * on a recovery-code pass, one stored code spent.
     */
    private function outcome(TwoFactorAuthenticatable&Model $user, #[SensitiveParameter] string $code): VerificationResult
    {
        $stored = count($user->twoFactorRecoveryCodes());

        // Like the real action: only a confirmed enrolment can pass a challenge,
        // whatever outcome is programmed, so a host test never passes a user the
        // real flow would refuse. The real action fires no event here either.
        if (! $user->hasTwoFactorEnabled()) {
            return VerificationResult::failed($this->remainingRecoveryCodes ?? $stored);
        }

        if ($this->replays) {
            $this->dispatch(new TwoFactorReplayDetected($user, 0));

            return VerificationResult::failed($this->remainingRecoveryCodes ?? $stored, replayed: true);
        }

        if (! $this->passes($code)) {
            $this->dispatch(new TwoFactorVerificationFailed($user));

            return VerificationResult::failed($this->remainingRecoveryCodes ?? $stored);
        }

        if ($this->method === TwoFactorMethod::RecoveryCode) {
            $left = $this->spendRecoveryCode($user);
            $result = VerificationResult::via($this->method, $this->remainingRecoveryCodes ?? $left ?? max(0, $stored - 1));

            $this->dispatch(new RecoveryCodeConsumed($user, $result->remainingRecoveryCodes));
        } else {
            $result = VerificationResult::via($this->method, $this->remainingRecoveryCodes ?? $stored);
        }

        $this->dispatch(new TwoFactorVerified($user, $this->method));

        return $result;
    }

    /**
     * Spend one stored recovery code (the first), returning how many are left — or
     * null when the row is gone or holds none. Like the real action, the write goes
     * to a freshly-read row with timestamps off, never the caller's own instance,
     * and the reduced list is mirrored onto the caller's instance for read-back.
     */
    private function spendRecoveryCode(TwoFactorAuthenticatable&Model $user): ?int
    {
        /** @var (TwoFactorAuthenticatable&Model)|null $row */
        $row = $user->newQuery()->find($user->getKey());
        $codes = $row?->twoFactorRecoveryCodes() ?? [];

        if ($row === null || $codes === []) {
            return null;
        }

        $column = ConfigGuard::columns()['recovery_codes'];
        $remaining = array_slice($codes, 1);

        $row->timestamps = false;
        $row->setAttribute($column, $remaining);
        $row->save();

        $user->setAttribute($column, $remaining);
        $user->syncOriginalAttribute($column);

        return count($remaining);
    }

    /**
     * Resolved per dispatch, so an Event::fake() made after TwoFactor::fake() sees it.
     */
    private function dispatch(object $event): void
    {
        $this->container->make(Dispatcher::class)->dispatch($event);
    }

    private function passes(#[SensitiveParameter] string $code): bool
    {
        if ($this->onlyCode !== null) {
            return ConstantTime::equals($this->onlyCode, $code);
        }

        return $this->accepts;
    }
}
