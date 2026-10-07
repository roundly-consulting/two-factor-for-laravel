# Changelog

All notable changes to `two-factor-for-laravel` are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

### Changed

- Requires `roundly-consulting/crypto-for-laravel` `^1.0.1`: that release refuses empty, short
  (under 10 bytes) and all-zero OTP secrets, which this package now reports as
  `InvalidTwoFactorSecretException`.
- `TwoFactor::fake()`: `attempt()` now fails a user without confirmed two-factor, exactly like the
  real action, whatever outcome is programmed — a host test can no longer pass a challenge
  production would refuse. Tests that attempt for an un-enrolled user must enrol them first
  (`TwoFactor::for($user)->start()` then `->confirm('123456')` under the fake).
- `two-factor.cache.ttl` must now be at least (2 × `window` + 1) × `period` seconds (90 with the
  defaults); a shorter value throws `InvalidTwoFactorConfigException` when the cache replay guard
  resolves. A shorter entry expired while the claimed code was still valid, so the cache guard
  accepted the same code again. The shipped default (86400) is unaffected.

### Fixed

- A secret that is valid base32 but no usable key (empty, under 10 bytes or all zero bytes) now
  throws the new `InvalidTwoFactorSecretException` from `verify()`, `currentCode()`,
  `provisioningUri()` and `attempt()`. `verify()` used to report it as an invalid `window`, and
  `currentCode()` / `provisioningUri()` leaked crypto's own exceptions (`provisioningUri()` now
  also throws `InvalidBase32Exception` for malformed base32).
- `TwoFactor::verify()` now bounds an explicit `$window` to 0–2 steps, like the configured
  `window`; a wider one throws `InvalidTwoFactorConfigException` instead of being honoured up to
  ±10 steps.
- `TwoFactor::fake()`: a faked `attempt()` now fires the same events as the real action
  (`TwoFactorVerified`, `RecoveryCodeConsumed`, `TwoFactorVerificationFailed`,
  `TwoFactorReplayDetected`), and a recovery-code pass spends one stored code, so `status()` and
  `recoveryCodes()->remaining()` agree with the reported count.
- `confirm()` (`ConfirmEnrolment`) now verifies the code against the row it locks
  (`lockForUpdate()` inside a transaction), not the caller's in-memory secret, so a concurrent
  `start()` can no longer leave two-factor enabled on a secret the user never scanned. It re-checks
  that the row is still pending, writes only `confirmed_at` to that row (unrelated unsaved
  attributes on the passed model are no longer saved with it) and syncs the passed model.
- `php artisan about` no longer crashes when `two-factor.replay_guard` is set to a
  `ReplayGuardMode` case, and renders an `OtpAlgorithm` / `RecoveryCodeStorage` case as its value
  instead of the default.
- `attempt()` in hashed recovery-code mode no longer runs one `Hash::check` per stored code while
  holding the user-row lock (roughly 0.5–1.8 s per wrong code at bcrypt cost 10–12). The candidate
  is matched before the lock; under the lock only the matched entry is re-confirmed, so a code
  still can't be spent twice.

## 1.0.0 - 2026-10-03

Initial public release.

### Added

- Native RFC 6238 TOTP two-factor authentication with no third-party crypto dependencies,
  compatible with standard authenticator apps.
- The full lifecycle on one per-user handle, `TwoFactor::for($user)`: `start()`, `confirm()`,
  `attempt()`, `status()` (a `TwoFactorStatus` with `enabled`, `pending`,
  `recoveryCodesRemaining` and `confirmedAt`), `recoveryCodes()->regenerate()/remaining()` and
  `disable()`. The same API is injectable as the `TwoFactorService` contract
  (`TwoFactorManager`), and each use case is an action — `StartEnrolment`, `ConfirmEnrolment`,
  `AttemptTwoFactorCode`, `RegenerateRecoveryCodes`, `DisableTwoFactor`.
- User-model verbs (`startTwoFactorEnrolment()`, `confirmTwoFactor()`, `attemptTwoFactorCode()`,
  `verifyTwoFactorCode()`, `disableTwoFactor()`, `regenerateTwoFactorRecoveryCodes()`) that
  delegate to `TwoFactor::for($this)`.
- `otpauth://` provisioning URIs with a configurable, per-call issuer, ready to render as a QR
  code (server-side with `qr-for-laravel`, or in your front end).
- Login verification with `TwoFactor::for($user)->attempt()`, returning a `VerificationResult`
  that says whether a TOTP or a recovery code was used.
- Single-use recovery codes, hashed at rest by default (encrypted storage available), matched
  the way people type them: case, surrounding whitespace and the dash don't matter.
- Encrypted TOTP secrets, automatically hidden from model serialization.
- Constant-time comparison and atomic replay protection, so a code can never be used twice.
- A built-in per-user brute-force limiter (`two-factor.attempts`) that counts each attempt
  atomically before verifying it, so a burst of parallel guesses can't exceed the limit.
- A publishable, forward-only migration for the host's users table that adds only missing
  columns, so re-running it after a rollback or during `migrate:refresh` is safe.
- A documented one-off migration for apps moving from Laravel Fortify's stored format.
- Events for enrolment, confirmation, disabling, recovery codes, verification success and
  failure, replays and rate limiting.
- `TwoFactor` facade primitives (`generateSecret()`, `currentCode()`, `verify()`,
  `provisioningUri()`, `generateRecoveryCodes()`).
- `TwoFactor::fake()` (`TwoFactorFake`) for host-app tests: programmable attempt outcomes, and
  every enrolment write recorded — including through the model verbs — with
  `assertStarted/Confirmed/Regenerated/Disabled()` and their `assertNothing*()` twins.

### Changed

- The flat `TwoFactor::attempt($user, $code)` and `TwoFactor::verifyFor($user, $code)` are gone;
  use `TwoFactor::for($user)->attempt($code)` (and `->verified` for the bool).
- The implementation class `TwoFactor` is now `TwoFactorManager` (it shared its short name with
  the facade) and is no longer aliased in the container — inject `TwoFactorService`.
- The fake class `FakeTwoFactor` is now `TwoFactorFake`.
