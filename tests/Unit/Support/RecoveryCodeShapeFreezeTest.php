<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\Support\RecoveryCodeManager;

/**
 * Freezes the OUTPUT SHAPE and DISTRIBUTION of recovery-code generation so routing it
 * through crypto-for-laravel's `Random\Token::fromAlphabet()` is provably a no-op.
 *
 * These codes bypass 2FA entirely. A refactor that silently narrowed the alphabet, changed
 * the length, or skewed the draw would weaken every code minted afterwards while every
 * existing test stayed green — `RecoveryCodeManagerTest` asserts `/^[A-Z0-9]{5}-[A-Z0-9]{5}$/`,
 * which does NOT pin the real alphabet: it happily accepts an `O`, a character this package
 * deliberately excludes to keep codes unambiguous when read aloud or typed from paper.
 *
 * So the shape is pinned exactly here, and the distribution is compared against a REFERENCE
 * COPY of the pre-refactor generator (below) with a two-sample chi-square. "It compiles" is
 * not evidence about a CSPRNG's output.
 */

/**
 * The pre-refactor `RecoveryCodeManager::segment()`, verbatim, as it stood before the
 * crypto refactor. This is the behaviour being frozen — it is intentionally a duplicate
 * rather than a call into the package, because a reference that delegates to the code under
 * test proves nothing.
 */
function referenceSegment(): string
{
    $alphabet = 'ABCDEFGHIJKLMNPQRSTUVWXYZ0123456789';
    $max = strlen($alphabet) - 1;
    $segment = '';

    for ($i = 0; $i < 5; $i++) {
        $segment .= $alphabet[random_int(0, $max)];
    }

    return $segment;
}

/**
 * Two-sample chi-square homogeneity statistic over two character-frequency maps.
 *
 * @param  array<string, int>  $a
 * @param  array<string, int>  $b
 */
function chiSquareTwoSample(array $a, array $b): float
{
    $totalA = array_sum($a);
    $totalB = array_sum($b);
    $chi = 0.0;

    foreach (array_keys($a + $b) as $key) {
        $countA = $a[$key] ?? 0;
        $countB = $b[$key] ?? 0;
        $combined = $countA + $countB;

        if ($combined === 0) {
            continue;
        }

        $expectedA = $combined * $totalA / ($totalA + $totalB);
        $expectedB = $combined * $totalB / ($totalA + $totalB);

        $chi += (($countA - $expectedA) ** 2) / $expectedA;
        $chi += (($countB - $expectedB) ** 2) / $expectedB;
    }

    return $chi;
}

/**
 * @return array<string, int>
 */
function characterFrequency(string $sample): array
{
    /** @var array<string, int> $frequency */
    $frequency = count_chars($sample, 1);

    $mapped = [];

    foreach ($frequency as $ordinal => $count) {
        $mapped[chr((int) $ordinal)] = $count;
    }

    return $mapped;
}

it('freezes the exact recovery-code format: two 5-char segments joined by a hyphen', function (): void {
    $codes = (new RecoveryCodeManager)->generate(50);

    foreach ($codes as $code) {
        // Pinned to the REAL alphabet, not [A-Z0-9]: `O` is excluded on purpose.
        expect($code)->toMatch('/^[ABCDEFGHIJKLMNPQRSTUVWXYZ0123456789]{5}-[ABCDEFGHIJKLMNPQRSTUVWXYZ0123456789]{5}$/')
            ->and(strlen($code))->toBe(11);
    }
});

it('freezes the alphabet: never emits the ambiguous letter O', function (): void {
    // 2000 codes * 10 chars = 20k draws. If `O` were in the alphabet, P(absent) ~ 0.
    $sample = implode('', (new RecoveryCodeManager)->generate(2000));

    expect(str_contains($sample, 'O'))->toBeFalse(
        'Recovery codes must never contain "O" — the alphabet excludes it so codes stay unambiguous on paper.',
    );
});

it('freezes the alphabet: every one of the 35 permitted characters is reachable', function (): void {
    $sample = str_replace('-', '', implode('', (new RecoveryCodeManager)->generate(3000)));

    // strval: PHP coerces numeric-string array keys to ints, so the digits come back as
    // int 0..9 and would not compare identical to the expected string list.
    $seen = array_map(strval(...), array_keys(characterFrequency($sample)));
    sort($seen);

    $expected = str_split('ABCDEFGHIJKLMNPQRSTUVWXYZ0123456789');
    sort($expected);

    // Pins the support exactly: nothing missing (a narrowed alphabet = weaker codes) and
    // nothing extra (a widened alphabet = a changed, unfrozen shape).
    expect($seen)->toBe($expected)
        ->and($seen)->toHaveCount(35);
});

it('freezes the distribution: output is statistically indistinguishable from the pre-refactor generator', function (): void {
    $new = str_replace('-', '', implode('', (new RecoveryCodeManager)->generate(5000)));

    $reference = '';
    for ($i = 0; $i < 10000; $i++) {
        $reference .= referenceSegment();
    }

    $chi = chiSquareTwoSample(characterFrequency($new), characterFrequency($reference));

    // df = 33. Threshold 100 sits ~8 sigma above the mean (33, sd 8.1), so a true no-op
    // effectively never trips it, while any real regression — a dropped character, a skewed
    // draw — lands far beyond it (one missing char alone contributes hundreds).
    expect($chi)->toBeLessThan(100.0);
});
