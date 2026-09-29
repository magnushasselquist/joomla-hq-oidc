<?php
/**
 * @package     plg_system_hqoidc
 * @copyright   (C) 2026 Magnus Hasselquist
 * @license     GPL-2.0-or-later
 */

namespace Joomla\Plugin\System\HqOidc\Tests\Support;

use Joomla\Plugin\System\HqOidc\Oidc\Discovery;

/**
 * Real discovery documents captured from public providers. Regenerate with
 * curl against the issuer's /.well-known/openid-configuration when a
 * provider changes something worth tracking.
 */
final class Fixtures
{
    public const KEYCLOAK_ISSUER = 'https://dev.id.scouterna.se/realms/scoutnet';
    public const GOOGLE_ISSUER   = 'https://accounts.google.com';

    public static function read(string $name): string
    {
        $contents = file_get_contents(__DIR__ . '/../fixtures/' . $name);

        if ($contents === false) {
            throw new \LogicException('Missing fixture ' . $name);
        }

        return $contents;
    }

    public static function keycloak(): Discovery
    {
        return Discovery::fromJson(self::read('discovery-keycloak.json'), self::KEYCLOAK_ISSUER);
    }

    public static function google(): Discovery
    {
        return Discovery::fromJson(self::read('discovery-google.json'), self::GOOGLE_ISSUER);
    }
}
