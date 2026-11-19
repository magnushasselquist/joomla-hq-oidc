<?php
/**
 * @package     plg_system_hqoidc
 * @copyright   (C) 2026 Magnus Hasselquist
 * @license     GPL-2.0-or-later
 */

namespace Joomla\Plugin\System\HqOidc\Tests\Oidc;

use Joomla\Plugin\System\HqOidc\Oidc\Claims;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ClaimsTest extends TestCase
{
    /**
     * @return iterable<string, array{0: array<string, mixed>, 1: bool}>
     */
    public static function emailVerifiedCases(): iterable
    {
        yield 'verified'             => [['email' => 'a@example.org', 'email_verified' => true], false];
        yield 'claim absent'         => [['email' => 'a@example.org'], false];
        yield 'unverified'           => [['email' => 'a@example.org', 'email_verified' => false], true];
        yield 'unverified as string' => [['email' => 'a@example.org', 'email_verified' => 'False'], true];
        yield 'verified as string'   => [['email' => 'a@example.org', 'email_verified' => 'true'], false];
    }

    /**
     * @param array<string, mixed> $claims
     */
    #[DataProvider('emailVerifiedCases')]
    public function testEmailUnverified(array $claims, bool $expected): void
    {
        self::assertSame($expected, Claims::emailUnverified($claims));
    }
}
