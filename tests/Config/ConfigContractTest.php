<?php

declare(strict_types=1);

use Illuminate\Support\Arr;

/**
 * The config file and the code that reads it are one contract, and it breaks in
 * both directions:
 *
 * - a key the code READS but the file does not SHIP silently resolves to null
 *   (for a 2FA package that means an empty algorithm or a missing column name);
 * - a key the file SHIPS and documents but no code READS is a dead feature — a
 *   host configures it, nothing happens, and only the docs claim otherwise.
 *
 * Both directions are pinned by scraping the real `config('two-factor.…')`
 * literals out of `src/` with the tokenizer, so a docblock mentioning a key is
 * never mistaken for a read.
 */

/**
 * Every literal `two-factor.*` key read via `config()` in the given files.
 *
 * @param  list<string>  $files
 * @return list<string>
 */
function readConfigKeys(array $files): array
{
    $keys = [];

    foreach ($files as $file) {
        $tokens = token_get_all((string) file_get_contents($file));
        $count = count($tokens);

        for ($i = 0; $i < $count; $i++) {
            $token = $tokens[$i];

            if (! is_array($token) || $token[0] !== T_STRING || $token[1] !== 'config') {
                continue;
            }

            // config( '<literal>' — anything else (a variable, an interpolation,
            // an array write) is deliberately not counted as a read.
            $next = $tokens[$i + 1] ?? null;
            $argument = $tokens[$i + 2] ?? null;

            if ($next !== '(' || ! is_array($argument) || $argument[0] !== T_CONSTANT_ENCAPSED_STRING) {
                continue;
            }

            $key = trim($argument[1], "'\"");

            if (str_starts_with($key, 'two-factor.')) {
                $keys[] = $key;
            }
        }
    }

    return array_values(array_unique($keys));
}

/**
 * @return list<string>
 */
function sourceFiles(string ...$excluding): array
{
    $files = [];

    /** @var SplFileInfo $file */
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__.'/../../src', FilesystemIterator::SKIP_DOTS)) as $file) {
        if ($file->getExtension() !== 'php' || in_array($file->getBasename(), $excluding, true)) {
            continue;
        }

        $files[] = $file->getPathname();
    }

    sort($files);

    return $files;
}

/**
 * Every dotted leaf key in the shipped config file.
 *
 * @return list<string>
 */
function shippedConfigKeys(): array
{
    /** @var array<string, mixed> $config */
    $config = require __DIR__.'/../../config/two-factor.php';

    return array_values(array_map(
        static fn (string $key): string => 'two-factor.'.$key,
        array_keys(Arr::dot($config)),
    ));
}

it('reads only config keys the package actually ships', function (): void {
    $read = readConfigKeys(sourceFiles());

    // Guard the guard: the scraper must actually find the reads.
    expect($read)->toContain('two-factor.algorithm', 'two-factor.columns');

    /** @var array<string, mixed> $config */
    $config = require __DIR__.'/../../config/two-factor.php';

    foreach ($read as $key) {
        $path = substr($key, strlen('two-factor.'));

        expect(Arr::has($config, $path))->toBeTrue("src/ reads config('{$key}') but config/two-factor.php does not ship it");
    }
});

it('ships no config key the package never reads', function (): void {
    // The `about` payload only *renders* config; displaying a key is not applying
    // it, so it cannot vouch for a key being alive.
    $read = readConfigKeys(sourceFiles('AboutSection.php'));

    expect($read)->not->toBeEmpty();

    foreach (shippedConfigKeys() as $key) {
        // A key is read either directly or through a parent (`two-factor.columns`
        // is read whole and indexed in PHP).
        $covered = array_filter(
            $read,
            static fn (string $candidate): bool => $candidate === $key || str_starts_with($key, $candidate.'.'),
        );

        expect($covered)->not->toBeEmpty("config/two-factor.php ships '{$key}' but no line of src/ reads it");
    }
});
