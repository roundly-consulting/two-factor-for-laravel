<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\TwoFactor\Actions\RegenerateRecoveryCodes;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

/**
 * One user's recovery codes, returned by `TwoFactor::for($user)->recoveryCodes()`.
 *
 * Not final: the recording fake extends it.
 */
readonly class UserRecoveryCodes
{
    public function __construct(
        protected Container $container,
        protected TwoFactorAuthenticatable&Model $user,
    ) {}

    /**
     * Replace the user's recovery codes, returning the new plaintext set to
     * show once.
     *
     * @return list<string>
     */
    public function regenerate(): array
    {
        return $this->container->make(RegenerateRecoveryCodes::class)->execute($this->user);
    }

    /**
     * How many single-use recovery codes remain.
     */
    public function remaining(): int
    {
        return count($this->user->twoFactorRecoveryCodes());
    }
}
