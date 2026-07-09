<?php

declare(strict_types=1);

/*
 * TOTP parity vectors — COMMITTED STATIC FIXTURE.
 *
 * Each row is [base32-secret, unix-timestamp, expected 6-digit code] for the
 * default TOTP profile (HMAC-SHA1, 6 digits, 30s period). These are the exact
 * codes any RFC 6238 authenticator produces for the same secret+timestamp, so a
 * host migrating from another TOTP library keeps verifying every stored secret
 * unchanged.
 *
 * The default profile is plain RFC 6238 (SHA1/6/30) over an RFC 4648 base32
 * decoder, so standard authenticator output is byte-identical to this package's
 * native Totp. This table was generated ONCE, offline, and pinned here as a
 * regression guarantee — no third-party TOTP library is a dependency of this
 * package (not in require, not in require-dev); the vectors below stand in for it.
 *
 * Provenance: generated 2026-07-09 from a standard RFC 6238 TOTP implementation,
 * cross-checked against RFC 6238 Appendix B and RFC 4226 Appendix D vectors
 * (see Rfc6238VectorsTest / Rfc4226VectorsTest). Regeneration is a manual,
 * documented one-off and is not part of the test suite or CI.
 *
 * @return list<array{0: string, 1: int, 2: string}>
 */

return [
    // secret ABCDEFGHIJKLMNOP (the reference test secret)
    ['ABCDEFGHIJKLMNOP', 0, '827178'],
    ['ABCDEFGHIJKLMNOP', 30, '317963'],
    ['ABCDEFGHIJKLMNOP', 59, '317963'],
    ['ABCDEFGHIJKLMNOP', 60, '625848'],
    ['ABCDEFGHIJKLMNOP', 90, '281014'],
    ['ABCDEFGHIJKLMNOP', 1111111111, '061275'],
    ['ABCDEFGHIJKLMNOP', 1234567890, '401870'],
    ['ABCDEFGHIJKLMNOP', 1500000000, '248600'],
    ['ABCDEFGHIJKLMNOP', 1600000000, '092806'],
    ['ABCDEFGHIJKLMNOP', 2000000000, '394754'],

    // secret JBSWY3DPEHPK3PXP (the canonical "Hello!" example secret)
    ['JBSWY3DPEHPK3PXP', 0, '282760'],
    ['JBSWY3DPEHPK3PXP', 30, '996554'],
    ['JBSWY3DPEHPK3PXP', 59, '996554'],
    ['JBSWY3DPEHPK3PXP', 60, '602287'],
    ['JBSWY3DPEHPK3PXP', 90, '143627'],
    ['JBSWY3DPEHPK3PXP', 1111111111, '358462'],
    ['JBSWY3DPEHPK3PXP', 1234567890, '742275'],
    ['JBSWY3DPEHPK3PXP', 1500000000, '914994'],
    ['JBSWY3DPEHPK3PXP', 1600000000, '368941'],
    ['JBSWY3DPEHPK3PXP', 2000000000, '890699'],
];
