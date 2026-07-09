<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\Tests\TestCase;

uses(TestCase::class)->in('Unit', 'Feature', 'ArchTest.php');

/**
 * The committed google2fa parity vectors.
 *
 * @return list<array{0: string, 1: int, 2: string}>
 */
function parityVectors(): array
{
    return require __DIR__.'/Fixtures/google2fa-parity.php';
}
