<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The host-owned `users` table the 2FA columns hang off. This package ships no
 * migration of its own that creates anything — its one migration is a publish-only
 * stub that ALTERs whatever users table the host already has — so this fixture
 * stands in for the host's own schema.
 *
 * It is a real migration rather than a `Schema::create()` in `setUp()` for a reason
 * the pgsql leg makes load-bearing: `PackageTestCase` resets a real engine by
 * dropping every table and re-migrating. A table built in `setUp()` outside the
 * migrator is dropped by that reset and never rebuilt, so the second test in a
 * Postgres run would find no `users` table at all. On sqlite `:memory:` the old
 * shape happened to work because the database dies with the connection.
 *
 * `twoFactorColumns()` is the package's own Blueprint macro — registered in the
 * provider's `register()`, which runs before the migrator, exactly as it does for a
 * host that published the stub.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('name')->nullable();
            $table->string('email')->nullable();
            $table->string('password')->nullable();
            $table->twoFactorColumns();
            $table->timestamps();
        });
    }
};
