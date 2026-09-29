<?php
/**
 * @package     plg_system_hqoidc
 * @copyright   (C) 2026 Magnus Hasselquist
 * @license     GPL-2.0-or-later
 */

namespace Joomla\Plugin\System\HqOidc\Oidc;

\defined('_JEXEC') or die;

/**
 * Any protocol-level failure: discovery, token exchange, token verification.
 * Messages are safe to log but must never contain token material.
 */
final class OidcException extends \RuntimeException
{
}
