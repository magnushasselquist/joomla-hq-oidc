<?php
/**
 * @package     plg_system_hqoidc
 * @copyright   (C) 2026 Magnus Hasselquist
 * @license     GPL-2.0-or-later
 */

namespace Joomla\Plugin\System\HqOidc\Oidc;

\defined('_JEXEC') or die;

final class HttpResponse
{
    public function __construct(
        public readonly int $status,
        public readonly string $body,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function json(string $what): array
    {
        $data = json_decode($this->body, true);

        if (!\is_array($data)) {
            throw new OidcException(sprintf('%s response is not a JSON object', $what));
        }

        return $data;
    }
}
