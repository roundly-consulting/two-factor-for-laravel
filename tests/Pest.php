<?php

declare(strict_types=1);

use RoundlyConsulting\TwoFactor\Tests\TestCase;

// ArchTest.php is listed explicitly because `runtimeRequireIsWhitelisted` and the
// crypto-@internal pin need the app booted — an arch file is not automatically
// test-cased, and Pest binds a test case per directory, not per file.
uses(TestCase::class)->in('Unit', 'Feature', 'Concurrency', 'Migrations', 'Config', 'ArchTest.php');
