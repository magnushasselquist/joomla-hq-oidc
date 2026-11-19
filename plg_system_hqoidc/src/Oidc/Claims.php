<?php
/**
 * @package     plg_system_hqoidc
 * @copyright   (C) 2026 Magnus Hasselquist
 * @license     GPL-2.0-or-later
 */

namespace Joomla\Plugin\System\HqOidc\Oidc;

\defined('_JEXEC') or die;

/**
 * Interpretation of standard claims (OIDC Core 5.1) beyond token validation.
 */
final class Claims
{
    /**
     * True only when the provider explicitly says the address is unverified.
     * An absent claim is not treated as unverified: plenty of providers omit
     * it, and refusing them would break email matching outright. Some
     * providers (older Cognito, some ADFS setups) send the string "false".
     *
     * @param array<string, mixed> $claims
     */
    public static function emailUnverified(array $claims): bool
    {
        $verified = $claims['email_verified'] ?? null;

        return $verified === false || (\is_string($verified) && strtolower($verified) === 'false');
    }
}
