<!-- roundly-hero:start -->
<p align="center">
  <a href="https://roundly-consulting.com/open-source/docs/two-factor-for-laravel?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=two-factor-for-laravel">
    <img src="art/hero.png" alt="Two-Factor Authentication for Laravel — Roundly open source" width="100%">
  </a>
</p>
<!-- roundly-hero:end -->

<!-- roundly-badges:start -->
<p align="center">
  <a href="https://packagist.org/packages/roundly-consulting/two-factor-for-laravel"><img src="https://img.shields.io/packagist/v/roundly-consulting/two-factor-for-laravel?style=flat-square&label=release" alt="Latest release"></a>
  <a href="https://github.com/roundly-consulting/two-factor-for-laravel/actions/workflows/run-tests.yml"><img src="https://img.shields.io/github/actions/workflow/status/roundly-consulting/two-factor-for-laravel/run-tests.yml?branch=main&style=flat-square&label=tests" alt="Tests"></a>
  <a href="https://github.com/roundly-consulting/two-factor-for-laravel/actions/workflows/fix-php-code-style-issues.yml"><img src="https://img.shields.io/github/actions/workflow/status/roundly-consulting/two-factor-for-laravel/fix-php-code-style-issues.yml?branch=main&style=flat-square&label=code%20style" alt="Code style"></a>
  <a href="https://donate.stripe.com/dRmeVe8FX5PF1Qd9pXcEw00"><img src="https://img.shields.io/badge/donate-support%20our%20open%20source-F24E29?style=flat-square&logo=stripe&logoColor=white" alt="Donate"></a>
  <a href="https://www.patreon.com/cw/roundly"><img src="https://img.shields.io/badge/patreon-become%20a%20patron-F96854?style=flat-square&logo=patreon&logoColor=white" alt="Patreon"></a>
  <a href="https://roundly-consulting.com/support-us?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=two-factor-for-laravel#crypto"><img src="https://img.shields.io/badge/crypto-BTC%20%C2%B7%20ETH%20%C2%B7%20BNB%20%C2%B7%20SOL-F7931A?style=flat-square&logo=bitcoin&logoColor=white" alt="Crypto"></a>
</p>
<!-- roundly-badges:end -->

# Two-Factor Authentication for Laravel

Native RFC 6238 TOTP two-factor authentication for Laravel — encrypted secrets, single-use
recovery codes and replay protection, with **zero third-party crypto dependencies**. QR
rendering is up to you: draw it client-side from the `otpauth://` URI, or server-side as an SVG
with our native [qr-for-laravel](https://github.com/roundly-consulting/qr-for-laravel). No image
library ships in this package.

- RFC 4226 / RFC 6238 TOTP and the RFC 4648 base32 codec, from our own
  [crypto-for-laravel](https://github.com/roundly-consulting/crypto-for-laravel).
- Constant-time verification and replay protection (a code can't be reused).
- Encrypted TOTP secret and hashed (one-way) recovery codes at rest, both hidden from serialization.
- One API three ways: the `TwoFactor` facade (`TwoFactor::for($user)->start()/confirm()/attempt()/status()`),
  the injectable `TwoFactorService` contract, or the action classes — plus a user-model trait,
  events and a recording `TwoFactor::fake()`.
- **Standards-compatible** — RFC 6238 secrets from other libraries keep producing the same codes,
  so nobody re-enrols (the stored columns are re-encrypted once — see
  [Migrating from another TOTP library](#migrating-from-another-totp-library)).

## Requirements

- PHP `^8.4`
- Laravel `^12.0 | ^13.0`

## Integrates with

- **[crypto-for-laravel](https://github.com/roundly-consulting/crypto-for-laravel)** — a hard
  dependency that owns every cryptographic primitive this package uses: the HOTP/TOTP maths
  (`Crypto\Otp\Totp`), the `otpauth://` provisioning URI, the strict base32 codec
  (`Crypto\Codec\Base32`), the CSPRNG secret generator (`Crypto\Random\Secret`), and the
  constant-time comparison. Nothing crypto is re-implemented here; this package owns the
  Laravel-side ceremony — enrolment, confirmation, replay guards, recovery codes, rate
  limiting, and the encrypted-at-rest columns.

  Crypto is **zero-config**: this package's own `config/two-factor.php` (algorithm, digits,
  period, window, secret length) still drives everything, and every failure is translated back
  into a `TwoFactorException` — a malformed secret still surfaces as `InvalidBase32Exception`,
  a bad code as `InvalidTwoFactorCodeException`, a bad setting as
  `InvalidTwoFactorConfigException`.

- **[package-toolkit-for-laravel](https://github.com/roundly-consulting/package-toolkit-for-laravel)**
  — a hard dependency that provides the service-provider base this package is built on: the
  config merge/publish wiring, the publish-only migration handling, and the
  `php artisan about --only=two-factor` section (which reports the TOTP parameters, the replay
  guard and the attempt limit — never a secret, a recovery code, the issuer or a store name).

- **[qr-for-laravel](https://github.com/roundly-consulting/qr-for-laravel)** — **optional
  (`suggest`)**, never installed by this package. Add it to your app to render the enrolment
  `otpauth://` URI as an SVG QR code server-side — see
  [Rendering the QR code](#rendering-the-qr-code). Two-factor itself stays QR-free.

## Installation

```bash
composer require roundly-consulting/two-factor-for-laravel
```

**Migrations are publish-only** — nothing is auto-loaded from the package, so publish the
migration (it stamps its own timestamp on publish) and then migrate:

```bash
php artisan vendor:publish --tag="two-factor-migrations"
php artisan migrate
```

Re-publishing overwrites the file it published to last time, so you never end up with two
copies of the same migration. The migration has a `down()` that drops the four columns again,
so `migrate:rollback` and `migrate:refresh` work as usual.

The migration adds four nullable columns to your `users` table — or to the table named by
`two-factor.table` (`TWO_FACTOR_TABLE`), read when the migration runs. If you write your own
migration instead, use the Blueprint macro:

```php
Schema::table('users', function (Blueprint $table): void {
    $table->twoFactorColumns(); // secret, recovery_codes, confirmed_at, last_used_timestep
});
```

### Other account tables

Two-factor works on any Eloquent model that uses the trait — `clients`, `admins`, one per
guard. The published migration covers one table; give every further account table the same
columns in your own migration with the macro:

```php
Schema::table('clients', function (Blueprint $table): void {
    $table->twoFactorColumns();
});
```

Column names come from the shared `two-factor.columns` map, and the built-in limiter keys on
the model class as well as the id, so a user and a client with the same id never share a
lockout.

Optionally publish the config file:

```bash
php artisan vendor:publish --tag="two-factor-config"
```

The package works with **zero configuration** — every key has a safe default.

## Configuration

`config/two-factor.php`:

```php
return [
    // TOTP parameters — defaults match standard authenticator apps (RFC 6238).
    // Bounds are enforced at runtime; out-of-range values throw
    // InvalidTwoFactorConfigException rather than silently weakening 2FA.
    'algorithm' => 'sha1',        // 'sha1' | 'sha256' | 'sha512'
    'digits' => 6,                // 6–8
    'period' => 30,               // 15–120 seconds per timestep
    'window' => 1,                // 0–2: accept ±N timesteps of drift
    'secret_length' => 32,        // base32 chars (≥16); 32 = 160 bits; 1/3/6 (mod 8) round up by one

    // Provisioning (otpauth:// URI). issuer falls back to config('app.name') at runtime.
    'issuer' => env('TWO_FACTOR_ISSUER'),

    'recovery_codes' => [
        'count' => 8,
        'storage' => 'hashed',    // 'hashed' (default) | 'encrypted'
    ],

    // Built-in brute-force limiter for attempt(), keyed per user. Set to null
    // to disable it and rely on your own throttle middleware instead.
    'attempts' => [
        'max' => 5,               // failed attempts before lockout
        'decay' => 60,            // seconds the lockout lasts
    ],

    // Replay protection: reject any code whose timestep <= the last successful one.
    'replay_guard' => 'column',   // 'column' | 'cache' | 'none' (null → none)
    'cache' => [
        'store' => env('TWO_FACTOR_CACHE_STORE'),
        'ttl' => 60 * 60 * 24,
    ],

    // The table the published migration adds the columns to. Other account
    // tables get them via `$table->twoFactorColumns()` in your own migration.
    'table' => env('TWO_FACTOR_TABLE', 'users'),

    // Column names on the host account table(s) — remap for non-standard schemas.
    'columns' => [
        'secret' => 'two_factor_secret',
        'recovery_codes' => 'two_factor_recovery_codes',
        'confirmed_at' => 'two_factor_confirmed_at',
        'last_used_timestep' => 'two_factor_last_used_timestep',
    ],
];
```

| Key | Type | Default | Purpose |
|---|---|---|---|
| `algorithm` | string | `sha1` | HMAC hash; `sha1` for authenticator-app compatibility |
| `digits` | int | `6` | Code length (6–8) |
| `period` | int | `30` | Seconds per timestep (15–120) |
| `window` | int | `1` | Accepted drift in ± timesteps (0–2) |
| `secret_length` | int | `32` | Base32 secret length (16–4096); 32 chars = 160 bits. A length no base32 string can have (1, 3 or 6 mod 8, e.g. 17 or 30) is rounded **up** one character, so the secret always decodes |
| `issuer` | string\|null | `env('TWO_FACTOR_ISSUER')` | Provisioning issuer; null or blank falls back to `config('app.name')` |
| `recovery_codes.count` | int | `8` | Recovery codes generated per enrolment |
| `recovery_codes.storage` | string | `hashed` | `hashed` (one-way, default) or `encrypted` (reversible, display-again) |
| `attempts` | array\|null | `['max' => 5, 'decay' => 60]` | Built-in per-user brute-force limiter; `null` disables it |
| `attempts.max` | int | `5` | Failed attempts before lockout |
| `attempts.decay` | int | `60` | Seconds the lockout lasts |
| `replay_guard` | string\|null | `column` | Last-used-timestep store: `column`, `cache`, or `none`/`null` |
| `cache.store` | string\|null | `env('TWO_FACTOR_CACHE_STORE')` | Cache store for the `cache` guard |
| `cache.ttl` | int | `86400` | Seconds to retain the last timestep in `cache` mode |
| `table` | string | `env('TWO_FACTOR_TABLE', 'users')` | Table the published migration alters; blank falls back to `users` |
| `columns.*` | string | — | Column names on every two-factor account table |

The `replay_guard` and `recovery_codes.storage` values are backed by the `ReplayGuardMode` and
`RecoveryCodeStorage` enums, and `algorithm` by crypto's `Otp\OtpAlgorithm` (`sha1` | `sha256` |
`sha512`) — an unknown value throws `InvalidTwoFactorConfigException` at resolution, never a
silent hash downgrade.

**Env vars:** `TWO_FACTOR_ISSUER`, `TWO_FACTOR_CACHE_STORE`, `TWO_FACTOR_TABLE`.

## Host model setup

Implement the contract, use the trait, and spread `twoFactorCasts()` into your model's casts:

```php
use Illuminate\Foundation\Auth\User as Authenticatable;
use RoundlyConsulting\TwoFactor\Concerns\HasTwoFactorAuthentication;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

final class User extends Authenticatable implements TwoFactorAuthenticatable
{
    use HasTwoFactorAuthentication;

    protected function casts(): array
    {
        return [
            // ...your other casts
            ...$this->twoFactorCasts(),
        ];
    }
}
```

## Usage

Everything that reads or changes one user's two-factor goes through `TwoFactor::for($user)`;
the stateless TOTP primitives stay flat on the facade.

```php
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;

$twoFactor = TwoFactor::for($user);

$setup  = $twoFactor->start(issuer: 'Acme');            // TwoFactorSetup — begin (or restart) enrolment
$twoFactor->confirm($code);                             // first authenticator code switches 2FA on
$result = $twoFactor->attempt($code);                   // VerificationResult — the login challenge
$status = $twoFactor->status();                         // TwoFactorStatus
$codes  = $twoFactor->recoveryCodes()->regenerate();    // list<string> — show once
$left   = $twoFactor->recoveryCodes()->remaining();     // int
$twoFactor->disable();                                  // clears every 2FA column
```

### Enrol

```php
$setup = TwoFactor::for($user)->start();

$setup->secret;          // base32 secret (store is handled for you)
$setup->provisioningUri; // otpauth://totp/Acme:user@acme.io?secret=...&issuer=Acme&...
$setup->recoveryCodes;   // list<string> — show these once, they are the only plaintext copy
$setup->issuer;          // the issuer the URI carries — show it next to the QR
```

`start()` throws `TwoFactorAlreadyEnabledException` when 2FA is already on. The issuer defaults
to `two-factor.issuer`, then `app.name` (a blank value at either level counts as unset). Brand it
per call — one name per guard or tenant — and override the account label the same way:

```php
$setup = TwoFactor::for($client)->start(label: 'billing@acme.io', issuer: 'Acme Partner Portal');
```

### Rendering the QR code

This package never renders a QR image — it hands you `$setup->provisioningUri`. Draw it
wherever suits your stack.

**Server-side (SVG)** — install our native
[qr-for-laravel](https://github.com/roundly-consulting/qr-for-laravel)
(`composer require roundly-consulting/qr-for-laravel`) and render the URI in one call:

```php
use RoundlyConsulting\Qr\Enums\ErrorCorrection;
use RoundlyConsulting\Qr\Facades\Qr;

$setup = TwoFactor::for($user)->start();

$svg = Qr::otpauth($setup->provisioningUri)
    ->size(240)
    ->errorCorrection(ErrorCorrection::Medium)
    ->title(__('Scan with your authenticator app'))
    ->svg();

// Blade:       {{ $svg }}  — renders the SVG markup; show {{ $setup->issuer }} next to it
// JSON API:    ['qr' => $svg->toDataUri(), 'issuer' => $setup->issuer]
// Controller:  return $svg;  — an image/svg+xml response
// Raw markup:  $svg->toString()
```

`Qr::otpauth()` encodes the URI **unchanged** and treats it as a secret: never memoised or
cached, served with `Cache-Control: no-store` and no ETag. The code carries the TOTP secret —
show it on the enrolment screen only; never persist, log or e-mail the SVG.

**Client-side** — pass `$setup->provisioningUri` to your front end and draw it there (e.g.
`qrcode.js`, `react-qr-code`). Send it over the same authenticated response as the rest of the
enrolment screen, and don't keep it once enrolment is confirmed.

### Confirm

The user scans the code and submits the first 6-digit code to finish enrolment:

```php
TwoFactor::for($user)->confirm($request->string('code')->toString());
// throws InvalidTwoFactorCodeException on a wrong code,
// TwoFactorNotPendingException if there is no pending enrolment — including when 2FA is
// already enabled: a confirm is never a silent no-op, so a clean return always means this
// code just switched 2FA on.
```

### Verify during login

```php
use RoundlyConsulting\TwoFactor\Enums\TwoFactorMethod;
use RoundlyConsulting\TwoFactor\Exceptions\TwoFactorRateLimitedException;

try {
    $result = TwoFactor::for($user)->attempt($request->string('code')->toString());
} catch (TwoFactorRateLimitedException $e) {
    // too many failed attempts — retry after $e->secondsUntilAvailable seconds
}

$result->verified;               // bool — TOTP (replay-safe) or a single-use recovery code
$result->method;                 // TwoFactorMethod::Totp | ::RecoveryCode | null on failure
$result->remainingRecoveryCodes; // int, after this attempt — "1 recovery code left"
$result->replayed;               // true when a valid code's timestep was already used

if ($result->method === TwoFactorMethod::RecoveryCode) {
    // e.g. notify the user, add 'recovery_code' to an amr claim
}
```

The remaining count after a recovery code is read from the row locked for the spend, so it is
correct even when two requests race.

`attempt()` checks the TOTP code with replay protection first, then falls back to a single-use
recovery code (consuming it). A code whose timestep was already used is rejected, and so is any
code for a user whose enrolment is still **pending** (`confirmed_at` unset) — only a confirmed
second factor can satisfy a challenge.

Recovery codes are matched the way people type them: case, surrounding whitespace and the dash
(or a space in its place) don't matter, and a typed letter `O` reads as the zero it was mistaken
for (codes never contain an `O`). So `ywnly 0j5bk` spends `YWNLY-0J5BK` — once. An imported code
of any other shape must match exactly.

**Built-in brute-force limiter.** `attempt()` throttles per user out of the box. Every attempt
is counted **before** it is verified, in one atomic increment, so even a burst of parallel
guesses gets at most `attempts.max` (default 5) verifications per `attempts.decay` seconds
(default 60). Past that, it throws `TwoFactorRateLimitedException` without doing any
verification work and dispatches a `TwoFactorRateLimited` event. A successful verification
clears the counter; a failed or replayed one stays counted. Set `config('two-factor.attempts')`
to `null` to disable it entirely and use your own `throttle:` middleware instead.

### Status

```php
$status = TwoFactor::for($user)->status();

$status->enabled;                // bool — a confirmed second factor
$status->pending;                // bool — enrolment started, waiting for its first code
$status->recoveryCodesRemaining; // int
$status->confirmedAt;            // ?CarbonImmutable — null unless enabled
```

### Recovery codes & disable

```php
$codes = TwoFactor::for($user)->recoveryCodes()->regenerate(); // new plaintext set — show once
$left  = TwoFactor::for($user)->recoveryCodes()->remaining();  // drive a "regenerate?" prompt

TwoFactor::for($user)->disable(); // clears all 2FA state
```

### On the user model (trait verbs)

`HasTwoFactorAuthentication` exposes the same lifecycle on the user itself. Every verb delegates
to `TwoFactor::for($this)`, so `TwoFactor::fake()` sees it:

```php
$setup  = $user->startTwoFactorEnrolment();          // → TwoFactorSetup (== ->start())
$user->confirmTwoFactor($code);                      // == ->confirm()
$result = $user->attemptTwoFactorCode($code);        // → VerificationResult (== ->attempt())
$ok     = $user->verifyTwoFactorCode($code);         // bool (== ->attempt()->verified)
$user->disableTwoFactor();                           // == ->disable()
$codes  = $user->regenerateTwoFactorRecoveryCodes(); // == ->recoveryCodes()->regenerate()

$user->twoFactorRecoveryCodesRemaining();            // int
```

Pass a label and/or an issuer —
`startTwoFactorEnrolment('billing@acme.io', issuer: 'Acme Billing')` — or override
`twoFactorLabel()` on the model to key the provisioning URI on a username/phone instead of
the default (email → primary key).

### TOTP primitives

```php
$secret = TwoFactor::generateSecret();                          // base32
$code   = TwoFactor::currentCode($secret);                      // current 6-digit code
$step   = TwoFactor::verify($secret, $code);                    // int timestep | false
$uri    = TwoFactor::provisioningUri($secret, 'user@acme.io');  // otpauth:// URI
$codes  = TwoFactor::generateRecoveryCodes();                   // list<string>
```

`verify()` is the bare RFC 6238 check — no replay guard, no recovery codes, no limiter. Use
`TwoFactor::for($user)->attempt()` for a login challenge.

### Without the facade

The facade root is the `TwoFactorService` contract (implemented by `TwoFactorManager`). Inject
it for the same API — `TwoFactor::fake()` swaps this binding too:

```php
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorService;

final readonly class ChallengeController
{
    public function __construct(private TwoFactorService $twoFactor) {}

    public function __invoke(Request $request): Response
    {
        $result = $this->twoFactor->for($request->user())->attempt($request->string('code')->toString());
        // ...
    }
}
```

Or run a use case's action directly — each handle method is one action:

| Handle method | Action |
|---|---|
| `for($user)->start($label, $issuer)` | `StartEnrolment::execute($user, $label, $issuer)` |
| `for($user)->confirm($code)` | `ConfirmEnrolment::execute($user, $code)` |
| `for($user)->attempt($code)` | `AttemptTwoFactorCode::execute($user, $code)` |
| `for($user)->recoveryCodes()->regenerate()` | `RegenerateRecoveryCodes::execute($user)` |
| `for($user)->disable()` | `DisableTwoFactor::execute($user)` |

```php
use RoundlyConsulting\TwoFactor\Actions\StartEnrolment;

$setup = app(StartEnrolment::class)->execute($user, issuer: 'Acme');
```

## Security

- **Encrypted secret at rest** — the TOTP secret is stored through Laravel's `encrypted` cast
  (your `APP_KEY`). Recovery codes are **hashed** one-way by default (see below).
- **Hidden from serialization** — the trait pushes `two_factor_secret`,
  `two_factor_recovery_codes`, and `two_factor_last_used_timestep` into the model's `$hidden`
  automatically, so `return $user;` from a route or `$user->toArray()`/`toJson()` never leaks
  the decrypted secret or codes. (`two_factor_confirmed_at` stays visible for UI state.)
- **Constant-time compare** — every code comparison goes through crypto's `ConstantTime`; the
  package never uses `===`, `md5`, or `sha1` for comparisons.
- **Atomic replay protection** — the matched timestep is claimed in a single check-and-set, so
  two concurrent submissions of the same code cannot both succeed. Any code with a timestep
  `<=` the last successful one is rejected and a `TwoFactorReplayDetected` event fires. The
  code used to *confirm* enrolment is claimed too, so it cannot double as the first login code.
  For multi-node hosts, use the `cache` guard backed by an atomic store (Redis / database).
- **Atomic single-use recovery codes** — consumption re-reads the row under a transaction lock
  before removing the matched code, so a code phished once cannot be raced through twice.
- **Built-in brute-force limiter** — `attempt()` ships a per-user throttle on by default
  (`attempts.max` / `attempts.decay`), throwing `TwoFactorRateLimitedException` on lockout. Each
  attempt is counted atomically before it is verified, so parallel requests can't slip extra
  guesses past the limit. Set `attempts` to `null` to opt out and run your own `throttle:`
  middleware.
- **Bounds-checked config** — `digits` (6–8), `period` (15–120), `window` (0–2) and
  `secret_length` (16–4096) are validated at runtime; a misconfiguration throws
  `InvalidTwoFactorConfigException` instead of silently degrading to weak 2FA.
- `#[SensitiveParameter]` is applied to every secret/code argument so they never leak into
  stack traces; the package never logs secrets or codes.

### Hashed vs. encrypted recovery codes

The default `hashed` mode stores one-way `Hash::make()` hashes — a database dump plus a leaked
`APP_KEY` never yields live recovery codes. The opt-in `encrypted` mode keeps the plaintext
codes encrypted at rest so a host can display them again after enrolment, at the cost of being
reversible with `APP_KEY`. **Switching modes invalidates existing stored codes** — only change
`recovery_codes.storage` on a fresh enrolment base, and regenerate codes for enrolled users if
you switch.

### Cache replay-guard caveat

The `cache` guard claims each timestep atomically via the store's lock (Redis, Memcached,
database, file, array all provide one). Be aware that a cache flush or eviction (`cache:clear`,
a deploy, LRU pressure) drops the last-used timestep and momentarily reopens the replay window.
Where that risk is unacceptable, use the default `column` guard, which persists to the users
table.

## Events

All events carry the user model (never a secret or a code); a few add a non-sensitive detail:

| Event | Fired when |
|---|---|
| `TwoFactorEnrolmentStarted` | `start()` persists a pending secret |
| `TwoFactorConfirmed` | `confirm()` enables 2FA |
| `TwoFactorDisabled` | `disable()` clears 2FA state |
| `RecoveryCodesRegenerated` | `recoveryCodes()->regenerate()` replaces the code set |
| `RecoveryCodeConsumed` | `attempt()` burns a recovery code (carries `remaining`, the count left) |
| `TwoFactorVerified` | a user passes a challenge (carries `method`: `TwoFactorMethod::Totp` or `::RecoveryCode`) |
| `TwoFactorVerificationFailed` | an enrolled user fails a challenge (not on replay/no-secret) |
| `TwoFactorReplayDetected` | a code with an already-used timestep is rejected |
| `TwoFactorRateLimited` | the built-in limiter locks a user out (carries `secondsUntilAvailable`) |

`TwoFactorVerified` / `TwoFactorVerificationFailed` let you audit challenges, meter
success/failure rates, and drive host-side lockout without wrapping the facade — e.g. a
listener that records a `LoginAttempt` or increments a rate limiter:

```php
Event::listen(function (TwoFactorVerificationFailed $event): void {
    RateLimiter::hit("2fa:{$event->user->getKey()}");
});
```

## Migrating from another TOTP library

TOTP itself is portable. This package follows the standard profile (SHA1, 6 digits, 30s) that
authenticator apps use, so a base32 secret minted by any RFC 6238 library keeps generating the
same codes: your users keep their authenticator entries and never re-enrol. Compatibility is
proven by committed static parity fixtures; no third-party TOTP library is a dependency of this
package.

What does **not** carry over by itself is how the old library *stored* the columns. This package
reads the secret through Laravel's `encrypted` cast (`Crypt::encryptString()`), and recovery codes
as a JSON list — encrypted the same way in `encrypted` storage, one-way hashes in `hashed`. Every
existing row has to be in that format, so plan a one-off data migration.

### From Laravel Fortify

Fortify uses the same column names but stores `encrypt($secret)` and
`encrypt(json_encode($codes))` — **serialized** payloads. Read as they are, the secret comes back
as `s:16:"…";` (every `attempt()` then throws `InvalidBase32Exception`) and the recovery codes as
an empty list. Don't publish this package's migration — the columns already exist. Instead, swap
Fortify's `TwoFactorAuthenticatable` trait for [`HasTwoFactorAuthentication`](#host-model-setup)
and run this migration once, under the same `APP_KEY`:

```php
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Fortify only adds two_factor_confirmed_at when its `confirm` option is on.
        $confirms = Schema::hasColumn('users', 'two_factor_confirmed_at');

        Schema::table('users', function (Blueprint $table) use ($confirms): void {
            if (! $confirms) {
                $table->timestamp('two_factor_confirmed_at')->nullable();
            }

            $table->unsignedBigInteger('two_factor_last_used_timestep')->nullable();
        });

        DB::table('users')->whereNotNull('two_factor_secret')->lazyById()->each(
            function (object $user) use ($confirms): void {
                DB::table('users')->where('id', $user->id)->update([
                    // Crypt::decrypt() unserializes Fortify's payload; encryptString() is what the cast reads.
                    'two_factor_secret' => Crypt::encryptString(Crypt::decrypt($user->two_factor_secret)),
                    'two_factor_recovery_codes' => $user->two_factor_recovery_codes === null
                        ? null
                        : Crypt::encryptString(Crypt::decrypt($user->two_factor_recovery_codes)),
                    // Without Fortify's confirmation step, every stored secret was a live second factor.
                    'two_factor_confirmed_at' => $confirms ? $user->two_factor_confirmed_at : now(),
                ]);
            },
        );
    }
};
```

Then keep the imported codes matchable — they arrive in plaintext, so store them reversibly:

```php
// config/two-factor.php
'recovery_codes' => [
    'count' => 8,
    'storage' => 'encrypted',
],
```

With confirmation on, a Fortify row that has a secret but no `two_factor_confirmed_at` was an
unfinished enrolment, and it stays pending here too. (If you switched Fortify's `confirm` off
after migrating, stamp `two_factor_confirmed_at` for those rows yourself.) To move to the default
`hashed` storage later, switch the setting and have users regenerate their codes — switching
modes invalidates stored codes.

### From other libraries

Apply the same rule per column: the secret must be `Crypt::encryptString($base32Secret)` —
wrap a plaintext value directly, or `Crypt::decrypt()` an `encrypt()`-serialized one first. Plaintext
recovery codes become `Crypt::encryptString(json_encode($codes))` under `encrypted` storage. Add
`two_factor_last_used_timestep` (and `two_factor_confirmed_at`, set for every enrolled user) if
the old schema lacks them.

## Testing

```bash
composer test
```

### Faking two-factor in host tests

`TwoFactor::fake()` swaps the service for a programmable, no-crypto double — the facade, the
injected `TwoFactorService` and the model verbs all see it — so you can assert your 2FA flow
without freezing the clock or computing real codes:

```php
use RoundlyConsulting\TwoFactor\Enums\TwoFactorMethod;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;

// Accept any code (the default) and assert the challenge was verified:
$fake = TwoFactor::fake()->accept();
$this->post('/login/2fa', ['code' => '123456'])->assertOk();
$fake->assertVerifiedFor($user);

// Reject every code:
TwoFactor::fake()->reject();
$this->post('/login/2fa', ['code' => '000000'])->assertStatus(422);

// Accept only a specific code:
TwoFactor::fake()->acceptCode('424242');

// Drive attempt(): pass via a recovery code, report 2 left, assert the method:
$fake = TwoFactor::fake()->acceptRecoveryCode()->withRemainingRecoveryCodes(2);
$this->post('/login/2fa', ['code' => 'ABCDE-12345'])->assertOk();
$fake->assertVerifiedVia(TwoFactorMethod::RecoveryCode);

// Fail as a replay (VerificationResult::$replayed === true):
TwoFactor::fake()->replay();

// Enrolment writes run for real on the fake's canned secret and codes, and are recorded:
$fake = TwoFactor::fake();
$this->post('/two-factor/enable')->assertOk();        // calls TwoFactor::for($user)->start()
$this->post('/two-factor/disable')->assertOk();       // or $user->disableTwoFactor()
$fake->assertStarted($user);
$fake->assertDisabled($user);
$fake->assertNothingRegenerated();
```

Programmable behaviour: `accept()` (passes via TOTP), `acceptRecoveryCode()`, `reject()`,
`replay()`, `acceptCode($code)`, `withRemainingRecoveryCodes($n)` (unset, the fake reports the
user's stored count, one lower when a recovery code passes), `withSecret($secret)`,
`withRecoveryCodes(...$codes)`.

Assertions (each throws a package exception, so they work under any runner; `$user` is
optional wherever it appears):

| Recorded call | Assert | Negative |
|---|---|---|
| `for($user)->attempt()` | `assertVerified()`, `assertVerifiedFor($user)`, `assertVerifiedVia($method)`, `assertVerificationFailed()`, `assertVerifyCount($n)`, `assertCodeAttempted($code)` | `assertNothingVerified()` |
| `for($user)->start()` | `assertStarted(?$user)` | `assertNothingStarted()` |
| `for($user)->confirm()` (successful) | `assertConfirmed(?$user)` | `assertNothingConfirmed()` |
| `for($user)->recoveryCodes()->regenerate()` | `assertRegenerated(?$user)` | `assertNothingRegenerated()` |
| `for($user)->disable()` | `assertDisabled(?$user)` | `assertNothingDisabled()` |

`status()` and `recoveryCodes()->remaining()` read through to the model. The fake is test-only
and performs no TOTP math — it is bound solely through `TwoFactor::fake()` and never in
production.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

<!-- roundly-support:start -->
## Support our work

This package is free and open source, built and maintained by
[Roundly Consulting](https://roundly-consulting.com/open-source?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=two-factor-for-laravel).
If it saves you time, please consider supporting our open-source work — a one-time donation, a
monthly pledge on Patreon or a crypto donation helps fund maintenance, new features and new
packages.

<a href="https://donate.stripe.com/dRmeVe8FX5PF1Qd9pXcEw00"><img src="https://img.shields.io/badge/Donate-Support%20Roundly%20open%20source-F24E29?style=for-the-badge&logo=stripe&logoColor=white" alt="Donate to Roundly open source"></a>
<a href="https://www.patreon.com/cw/roundly"><img src="https://img.shields.io/badge/Patreon-Become%20a%20patron-F96854?style=for-the-badge&logo=patreon&logoColor=white" alt="Become a patron on Patreon"></a>
<a href="https://roundly-consulting.com/support-us?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=two-factor-for-laravel#crypto"><img src="https://img.shields.io/badge/Crypto-BTC%20%C2%B7%20ETH%20%C2%B7%20BNB%20%C2%B7%20SOL-F7931A?style=for-the-badge&logo=bitcoin&logoColor=white" alt="Donate crypto: BTC, ETH, BNB or SOL"></a>
<!-- roundly-support:end -->

## License

The MIT License (MIT). Please see [LICENSE.md](LICENSE.md). Maintained by roundly-consulting.
