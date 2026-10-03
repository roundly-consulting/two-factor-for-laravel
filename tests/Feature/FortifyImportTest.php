<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use RoundlyConsulting\TwoFactor\Enums\TwoFactorMethod;
use RoundlyConsulting\TwoFactor\Exceptions\InvalidBase32Exception;
use RoundlyConsulting\TwoFactor\Facades\TwoFactor;
use RoundlyConsulting\TwoFactor\Tests\Fixtures\TwoFactorUser;

/**
 * The docs' "From Laravel Fortify" recipe (website docs: Migrating from Fortify), executed
 * exactly as printed — keep this copy and the docs identical. Fortify stores `encrypt()`
 * payloads — serialized — which this package's `encrypted` cast does not read, so
 * without the recipe an imported secret reads back as `s:N:"…";`.
 */
function fortifyRecipe(): Migration
{
    $recipe = <<<'PHP'
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
        PHP;

    $file = sys_get_temp_dir().'/two-factor-fortify-'.Str::random(8).'.php';
    file_put_contents($file, $recipe);

    try {
        return require $file;
    } finally {
        unlink($file);
    }
}

/**
 * A users table shaped the way Fortify leaves it: no replay-guard column, and a
 * `two_factor_confirmed_at` column only when Fortify's `confirm` option was on.
 *
 * @return array{0: int, 1: string, 2: list<string>}
 */
function fortifyUser(bool $confirms): array
{
    Schema::table('users', function (Blueprint $table) use ($confirms): void {
        $table->dropColumn($confirms
            ? ['two_factor_last_used_timestep']
            : ['two_factor_last_used_timestep', 'two_factor_confirmed_at']);
    });

    $secret = TwoFactor::generateSecret(16);
    $codes = array_map(static fn (): string => Str::random(10).'-'.Str::random(10), range(1, 8));

    $id = DB::table('users')->insertGetId(array_filter([
        'name' => 'fortify',
        'email' => 'fortify@acme.io',
        'two_factor_secret' => encrypt($secret),
        'two_factor_recovery_codes' => encrypt(json_encode($codes)),
        'two_factor_confirmed_at' => $confirms ? now() : null,
    ], static fn (mixed $value): bool => $value !== null));

    return [$id, $secret, $codes];
}

it('cannot read a fortify-written secret before the recipe runs', function (): void {
    [$id, $secret, $codes] = fortifyUser(confirms: true);

    config(['two-factor.recovery_codes.storage' => 'encrypted']);
    $user = TwoFactorUser::query()->findOrFail($id);

    expect($user->twoFactorSecret())->toStartWith('s:')
        ->and($user->twoFactorRecoveryCodes())->toBe([])
        ->and(fn () => TwoFactor::for($user)->attempt(TwoFactor::currentCode($secret)))
        ->toThrow(InvalidBase32Exception::class);
});

it('verifies fortify-written secrets and recovery codes after the readme recipe', function (bool $confirms): void {
    [$id, $secret, $codes] = fortifyUser($confirms);

    fortifyRecipe()->up();

    config(['two-factor.recovery_codes.storage' => 'encrypted']);
    $user = TwoFactorUser::query()->findOrFail($id);

    expect($user->hasTwoFactorEnabled())->toBeTrue()
        ->and($user->twoFactorSecret())->toBe($secret)
        ->and($user->twoFactorRecoveryCodes())->toBe($codes);

    expect(TwoFactor::for($user)->attempt(TwoFactor::currentCode($secret)))
        ->verified->toBeTrue()
        ->method->toBe(TwoFactorMethod::Totp);

    expect(TwoFactor::for($user)->attempt($codes[0]))
        ->verified->toBeTrue()
        ->method->toBe(TwoFactorMethod::RecoveryCode)
        ->remainingRecoveryCodes->toBe(7);

    // Replay protection is live on the column the recipe added.
    expect(TwoFactor::for($user->fresh())->attempt(TwoFactor::currentCode($secret))->replayed)->toBeTrue();
})->with([
    'fortify with confirmation' => true,
    'fortify without confirmation' => false,
]);

it('leaves an unfinished fortify enrolment pending', function (): void {
    [$id] = fortifyUser(confirms: true);
    DB::table('users')->where('id', $id)->update(['two_factor_confirmed_at' => null]);

    fortifyRecipe()->up();

    $user = TwoFactorUser::query()->findOrFail($id);

    expect($user->hasPendingTwoFactor())->toBeTrue()
        ->and($user->hasTwoFactorEnabled())->toBeFalse();
});
