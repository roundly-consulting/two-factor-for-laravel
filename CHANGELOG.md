# Changelog

All notable changes to `two-factor-for-laravel` are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

Initial public release.

### Added

- Native RFC 6238 TOTP two-factor authentication with no third-party crypto dependencies,
  compatible with standard authenticator apps.
- The full lifecycle as actions and user-model verbs: `StartEnrolment` /
  `startTwoFactorEnrolment()`, `ConfirmEnrolment`, `DisableTwoFactor` and
  `RegenerateRecoveryCodes`.
- `otpauth://` provisioning URIs with a configurable, per-call issuer, ready to render as a QR
  code (server-side with `qr-for-laravel`, or in your front end).
- Login verification with `TwoFactor::verifyFor()`, or `TwoFactor::attempt()` returning a
  `VerificationResult` that says whether a TOTP or a recovery code was used.
- Single-use recovery codes, hashed at rest by default (encrypted storage available).
- Encrypted TOTP secrets, automatically hidden from model serialization.
- Constant-time comparison and atomic replay protection, so a code can never be used twice.
- A built-in per-user brute-force limiter (`two-factor.attempts`).
- Events for enrolment, confirmation, disabling, recovery codes, verification success and
  failure, replays and rate limiting.
- `TwoFactor` facade primitives (`generateSecret()`, `currentCode()`, `provisioningUri()`) and
  `TwoFactor::fake()` for host-app tests.
