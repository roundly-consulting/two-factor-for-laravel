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
