<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Exceptions;

use RoundlyConsulting\TwoFactor\Testing\FakeTwoFactor;

/**
 * Thrown by {@see FakeTwoFactor} when one of its assertions fails. It is a
 * package exception (not a PHPUnit assertion) so the fake stays runtime-only
 * and works under any test runner.
 */
final class TwoFactorAssertionFailedException extends TwoFactorException {}
