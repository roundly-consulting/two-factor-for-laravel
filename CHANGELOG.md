# Changelog

All notable changes to `two-factor-for-laravel` will be documented in this file.

## 1.0.0 - Unreleased

- Initial release.
- Native RFC 4226 / RFC 6238 TOTP (`hash_hmac` + RFC 4648 base32), constant-time
  verification with `hash_equals`, and a configurable drift window.
- Enrolment lifecycle actions: `StartEnrolment`, `ConfirmEnrolment`, `DisableTwoFactor`,
  `RegenerateRecoveryCodes`, returning a `TwoFactorSetup` DTO.
- `TwoFactor` facade + singleton service with a replay-safe, recovery-aware `verifyFor()`.
- Encrypted secret + recovery-code storage (Laravel `encrypted` casts) with an opt-in,
  config-gated `hashed` recovery-code mode.
- Replay protection via a pluggable `ReplayGuard` (`column`, `cache`, `null`).
- `HasTwoFactorAuthentication` trait + `TwoFactorAuthenticatable` contract, a
  `twoFactorColumns()` Blueprint macro, and a publishable migration stub.
- Package events for every lifecycle transition and for replay detection.
- Zero third-party runtime dependencies; google2fa byte-compatibility proven by committed
  static parity fixtures.
- `TwoFactorService` contract + a shipped `FakeTwoFactor` testing double swapped in by
  `TwoFactor::fake()` (programmable `accept()`/`reject()`/`acceptCode()`, canned outputs, call
  recording, and runner-agnostic assertions) — assert your 2FA flow without real TOTP math.
- `TwoFactorVerified` and `TwoFactorVerificationFailed` events on the success/failure branches
  of `verifyFor()`, for audit trails, success/failure metering, and host-side lockout.
- Trait action verbs on `HasTwoFactorAuthentication`: `startTwoFactorEnrolment()`,
  `confirmTwoFactor()`, `verifyTwoFactorCode()`, `disableTwoFactor()`,
  `regenerateTwoFactorRecoveryCodes()`, plus `twoFactorRecoveryCodesRemaining()` and an
  overridable `twoFactorLabel()` provisioning-label hook.
- Security: the enrolment-confirmation code's timestep is now recorded in the replay guard, so
  it can no longer be replayed once at the first login.
