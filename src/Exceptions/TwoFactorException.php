<?php

declare(strict_types=1);

namespace RoundlyConsulting\TwoFactor\Exceptions;

use RuntimeException;

/**
 * Base type for every exception the package throws, so hosts can catch the
 * whole family with a single `catch (TwoFactorException $e)`.
 */
abstract class TwoFactorException extends RuntimeException {}
