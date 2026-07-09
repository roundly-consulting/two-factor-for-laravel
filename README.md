# Two-Factor Authentication for Laravel

Native RFC 6238 TOTP two-factor authentication for Laravel — encrypted secrets, single-use
recovery codes and replay protection, with **zero third-party crypto dependencies**. The QR
code is rendered client-side from the `otpauth://` URI, so no image library ships here.

- RFC 4226 / RFC 6238 TOTP built on `hash_hmac` + a native RFC 4648 base32 codec.
- Constant-time verification (`hash_equals`) and replay protection (a code can't be reused).
- Encrypted secret + recovery-code storage via Laravel's `encrypted` casts.
- Ergonomic surface: a `TwoFactor` facade, lifecycle Actions, a user-model trait, and events.
- **google2fa-compatible** — existing google2fa secrets keep verifying unchanged.

## Requirements

- PHP `^8.4`
- Laravel `^12.0 | ^13.0`

## Installation

```bash
composer require roundly-consulting/two-factor-for-laravel
```

Publish the migration (it stamps its own timestamp on publish) and run it:

```bash
php artisan vendor:publish --tag="two-factor-migrations"
php artisan migrate
```

The migration adds four nullable columns to your `users` table. If you write your own
migration instead, use the Blueprint macro:

```php
Schema::table('users', function (Blueprint $table): void {
    $table->twoFactorColumns(); // secret, recovery_codes, confirmed_at, last_used_timestep
});
```

Optionally publish the config file:

```bash
php artisan vendor:publish --tag="two-factor-config"
```

The package works with **zero configuration** — every key has a safe default.

## Configuration

`config/two-factor.php`:

```php
return [
    // TOTP parameters — defaults match google2fa / standard authenticator apps.
    'algorithm' => 'sha1',        // 'sha1' | 'sha256' | 'sha512'
    'digits' => 6,
    'period' => 30,               // seconds per timestep
    'window' => 1,                // accept ±N timesteps of drift
    'secret_length' => 16,        // base32 chars

    // Provisioning (otpauth:// URI). issuer falls back to config('app.name') at runtime.
    'issuer' => env('TWO_FACTOR_ISSUER'),

    'recovery_codes' => [
        'count' => 8,
        'storage' => 'encrypted', // 'encrypted' (default) | 'hashed'
    ],

    // Replay protection: reject any code whose timestep <= the last successful one.
    'replay_guard' => 'column',   // 'column' | 'cache' | null
    'cache' => [
        'store' => env('TWO_FACTOR_CACHE_STORE'),
        'ttl' => 60 * 60 * 24,
    ],

    // Column names on the host users table — remap for non-standard schemas.
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
| `digits` | int | `6` | Code length |
| `period` | int | `30` | Seconds per timestep |
| `window` | int | `1` | Accepted drift in ± timesteps |
| `secret_length` | int | `16` | Base32 secret length |
| `issuer` | string\|null | `env('TWO_FACTOR_ISSUER')` | Provisioning issuer; falls back to `config('app.name')` |
| `recovery_codes.count` | int | `8` | Recovery codes generated per enrolment |
| `recovery_codes.storage` | string | `encrypted` | `encrypted` (reversible) or `hashed` (one-way) |
| `replay_guard` | string\|null | `column` | Last-used-timestep store: `column`, `cache`, or `null` |
| `cache.store` | string\|null | `env('TWO_FACTOR_CACHE_STORE')` | Cache store for the `cache` guard |
| `cache.ttl` | int | `86400` | Seconds to retain the last timestep in `cache` mode |
| `columns.*` | string | — | Column names on the `users` table |

**Env vars:** `TWO_FACTOR_ISSUER`, `TWO_FACTOR_CACHE_STORE`.

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

### Enrol

```php
use RoundlyConsulting\TwoFactor\Actions\StartEnrolment;

$setup = app(StartEnrolment::class)->execute($user);

$setup->secret;          // base32 secret (store is handled for you)
$setup->provisioningUri; // otpauth://totp/Acme:user@acme.io?secret=...&issuer=Acme&...
$setup->recoveryCodes;   // list<string> — show these once, they are the only plaintext copy
```

Render the QR **client-side** from `$setup->provisioningUri` (e.g. `qrcode.js`,
`react-qr-code`). This package never renders a QR image.

### Confirm

The user scans the code and submits the first 6-digit code to finish enrolment:

```php
use RoundlyConsulting\TwoFactor\Actions\ConfirmEnrolment;

app(ConfirmEnrolment::class)->execute($user, $request->string('code'));
// throws InvalidTwoFactorCodeException on a wrong code,
// TwoFactorNotPendingException if there is no pending enrolment.
```

### Verify during login

```php
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;

if (TwoFactor::verifyFor($user, $request->string('code'))) {
    // accepted — TOTP (replay-safe) or a single-use recovery code
}
```

`verifyFor()` checks the TOTP code with replay protection first, then falls back to a
single-use recovery code (consuming it). A code whose timestep was already used is rejected.

### Disable & regenerate

```php
use RoundlyConsulting\TwoFactor\Actions\DisableTwoFactor;
use RoundlyConsulting\TwoFactor\Actions\RegenerateRecoveryCodes;

app(DisableTwoFactor::class)->execute($user);          // clears all 2FA state
$codes = app(RegenerateRecoveryCodes::class)->execute($user); // returns the new codes
```

### Facade primitives

```php
$secret = TwoFactor::generateSecret();                          // base32
$code   = TwoFactor::currentCode($secret);                      // current 6-digit code
$step   = TwoFactor::verify($secret, $code);                    // int timestep | false
$uri    = TwoFactor::provisioningUri($secret, 'user@acme.io');  // otpauth:// URI
$codes  = TwoFactor::generateRecoveryCodes();                   // list<string>
```

## Security

- **Encrypted at rest** — the secret and recovery codes are stored through Laravel's
  `encrypted` casts (your `APP_KEY`).
- **Constant-time compare** — every code comparison uses `hash_equals`; the package never
  uses `===`, `md5`, or `sha1` for comparisons.
- **Replay protection** — the matched timestep is persisted; any code with a timestep `<=`
  the last successful one is rejected and a `TwoFactorReplayDetected` event fires. For
  multi-node hosts, use the `cache` guard backed by an atomic store (Redis / database).
- **Single-use recovery codes** — a consumed recovery code is removed from the stored set.
- **Rate limiting is the host's job** — apply a `throttle:` middleware to your 2FA challenge
  route; the package ships no limiter but surfaces typed exceptions and events to drive one.
- `#[SensitiveParameter]` is applied to every secret/code argument so they never leak into
  stack traces; the package never logs secrets or codes.

### Encrypted vs. hashed recovery codes

The default `encrypted` mode keeps the plaintext codes encrypted at rest, so they can be
compared literally. The opt-in `hashed` mode stores one-way `Hash::make()` hashes instead.
**Switching modes invalidates existing stored codes** — only change `recovery_codes.storage`
on a fresh enrolment base, and regenerate codes for enrolled users if you switch.

## Events

All events carry the user model only (no secrets/codes):

| Event | Fired when |
|---|---|
| `TwoFactorEnrolmentStarted` | `StartEnrolment` persists a pending secret |
| `TwoFactorConfirmed` | `ConfirmEnrolment` enables 2FA |
| `TwoFactorDisabled` | `DisableTwoFactor` clears 2FA state |
| `RecoveryCodesRegenerated` | `RegenerateRecoveryCodes` replaces the code set |
| `RecoveryCodeConsumed` | `verifyFor` burns a recovery code |
| `TwoFactorReplayDetected` | a code with an already-used timestep is rejected |

## Migrating from google2fa

This package is **byte-compatible** with `pragmarx/google2fa` for the default TOTP profile
(SHA1, 6 digits, 30s). Existing secrets and encrypted recovery codes keep verifying under the
same `APP_KEY` with no data migration — just add the `two_factor_last_used_timestep` column
(via the macro/migration) to enable replay protection. Compatibility is proven by committed
static parity fixtures; google2fa is **not** a dependency of this package.

## Testing

```bash
composer test
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

The MIT License (MIT). Please see [LICENSE.md](LICENSE.md). Maintained by roundly-consulting.
