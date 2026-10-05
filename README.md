<!-- roundly-hero:start -->
<p align="center">
  <a href="https://roundly-consulting.com/open-source/docs/two-factor-for-laravel?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=two-factor-for-laravel">
    <img src="https://raw.githubusercontent.com/roundly-consulting/two-factor-for-laravel/main/art/hero.png" alt="Two-Factor Authentication for Laravel — Roundly open source" width="100%">
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

Native RFC 6238 TOTP two-factor authentication for Laravel: encrypted secrets, single-use
recovery codes, replay protection and a built-in brute-force limiter, with no third-party crypto
dependencies. It hands you the `otpauth://` URI, so you render the QR code wherever suits your
stack.

## Installation

Requires PHP 8.4, Laravel 12 or 13.

```bash
composer require roundly-consulting/two-factor-for-laravel
php artisan vendor:publish --tag="two-factor-migrations"
php artisan migrate
```

The migration adds four nullable columns to your `users` table. If your accounts live in another
table, set `TWO_FACTOR_TABLE` **before** migrating.

## Usage

Prepare the user model:

```php
use Illuminate\Foundation\Auth\User as Authenticatable;
use RoundlyConsulting\TwoFactor\Concerns\HasTwoFactorAuthentication;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

final class User extends Authenticatable implements TwoFactorAuthenticatable
{
    use HasTwoFactorAuthentication;

    protected function casts(): array
    {
        return [...$this->twoFactorCasts()];
    }
}
```

Enrol, confirm with the first code, then challenge at login:

```php
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;

$setup = TwoFactor::for($user)->start(issuer: 'Acme');
$setup->provisioningUri;                          // otpauth://totp/Acme:… — render it as a QR code
$setup->recoveryCodes;                            // list<string> — show these once

TwoFactor::for($user)->confirm($code);            // the first authenticator code switches 2FA on

$result = TwoFactor::for($user)->attempt($code);  // TOTP (replay-safe) or a single-use recovery code
$result->verified;                                // bool
$result->method;                                  // TwoFactorMethod::Totp | ::RecoveryCode | null

TwoFactor::for($user)->status()->enabled;         // true
```

<!-- roundly-docs:start -->
## Documentation

The full documentation — configuration, every feature and its API, and testing — lives on our
website: **[roundly-consulting.com/open-source/docs/two-factor-for-laravel](https://roundly-consulting.com/open-source/docs/two-factor-for-laravel?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=two-factor-for-laravel)**

Release notes are in [CHANGELOG.md](CHANGELOG.md). To contribute, see the
[contributing guide](https://github.com/roundly-consulting/.github/blob/main/CONTRIBUTING.md).
<!-- roundly-docs:end -->

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
