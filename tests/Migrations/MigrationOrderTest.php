<?php

declare(strict_types=1);

use Illuminate\Support\Str;

/**
 * Publish order == directory sort order, so a migration that touches a table an
 * earlier one has not created yet is unrunnable in a host — and SQLite will not
 * tell you: it happily creates a table whose foreign key names a table that does
 * not exist. The pin below is therefore **structural and engine-independent**:
 * it reads the sources, not a database.
 *
 * This package ships exactly one migration and it declares no foreign key, so
 * the pin is a regression guard for the day a second one lands.
 */

/**
 * The package's migration sources in the exact order they publish (and so run):
 * the directory's sort order.
 *
 * @return list<string>
 */
function migrationSources(): array
{
    /** @var list<string> $files */
    $files = array_values(array_filter(array_merge(
        (array) glob(__DIR__.'/../../database/migrations/*.php'),
        (array) glob(__DIR__.'/../../database/migrations/*.php.stub'),
    ), is_string(...)));

    sort($files);

    return $files;
}

/**
 * The tables a migration source depends on already existing: every table it
 * ALTERs, plus the parent of every foreign key it declares — in all three of
 * Laravel's forms.
 *
 * @return list<string>
 */
function dependsOnTables(string $body): array
{
    preg_match_all("/Schema::table\(\s*'([^']+)'/", $body, $alters);
    preg_match_all("/->constrained\(\s*'([^']+)'/", $body, $named);
    preg_match_all("/->references\(\s*'[^']+'\s*\)\s*->on\(\s*'([^']+)'/", $body, $referenced);
    preg_match_all("/foreignId(?:For)?\(\s*'([^']+)'\s*\)[^;]*?->constrained\(\s*\)/", $body, $bare);

    return array_values(array_unique(array_merge(
        $alters[1],
        $named[1],
        $referenced[1],
        array_map(
            static fn (string $column): string => Str::plural(Str::beforeLast($column, '_id')),
            $bare[1],
        ),
    )));
}

/**
 * @return list<string>
 */
function createsTables(string $body): array
{
    preg_match_all("/Schema::create\(\s*'([^']+)'/", $body, $creates);

    return array_values($creates[1]);
}

it('never touches a table before the migration that creates it', function (): void {
    // The one table this package does not own: it ALTERs the host's users table,
    // which exists long before anything is published from here.
    $available = ['users'];
    $checked = 0;

    foreach (migrationSources() as $file) {
        $body = (string) file_get_contents($file);
        $name = basename($file);

        // A table created in this same file can be referenced by it (a
        // self-referencing key), so fold this file's creates in before checking.
        $available = array_merge($available, createsTables($body));

        foreach (dependsOnTables($body) as $table) {
            $checked++;

            expect(in_array($table, $available, true))
                ->toBeTrue("{$name} touches '{$table}' before any earlier migration creates it");
        }
    }

    // Guard the guard: a parser that matched nothing would pass vacuously.
    expect($checked)->toBeGreaterThan(0);
});
