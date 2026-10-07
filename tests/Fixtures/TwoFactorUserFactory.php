<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Tests\Fixtures;

use Illuminate\Database\Eloquent\Factories\Factory;
use RoundlyConsulting\TwoFactor\Actions\StartEnrolment;

/**
 * @extends Factory<TwoFactorUser>
 */
final class TwoFactorUserFactory extends Factory
{
    protected $model = TwoFactorUser::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'name' => $this->faker->name(),
            'email' => $this->faker->unique()->safeEmail(),
            'password' => bcrypt('password'),
        ];
    }

    /**
     * A user with a confirmed enrolment (a fresh secret and recovery codes), as only a
     * confirmed enrolment can pass a challenge — under the fake too. Runs the action
     * directly, so a swapped-in fake records no enrolment start for it.
     */
    public function withTwoFactor(): self
    {
        return $this->afterCreating(static function (TwoFactorUser $user): void {
            app(StartEnrolment::class)->execute($user);

            $user->setAttribute((string) config('two-factor.columns.confirmed_at'), now());
            $user->save();
        });
    }
}
