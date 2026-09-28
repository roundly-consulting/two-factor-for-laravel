<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Testing;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;
use RoundlyConsulting\TwoFactor\UserRecoveryCodes;

/**
 * The recovery-code handle under `TwoFactor::fake()`: `regenerate()` runs the real
 * action and is recorded once it succeeds.
 */
final readonly class RecordingUserRecoveryCodes extends UserRecoveryCodes
{
    public function __construct(
        private TwoFactorFake $fake,
        Container $container,
        TwoFactorAuthenticatable&Model $user,
    ) {
        parent::__construct($container, $user);
    }

    public function regenerate(): array
    {
        $codes = parent::regenerate();

        $this->fake->recordRegenerated($this->user);

        return $codes;
    }
}
