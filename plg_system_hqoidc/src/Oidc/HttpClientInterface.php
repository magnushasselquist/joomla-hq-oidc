<?php
/**
 * @package     plg_system_hqoidc
 * @copyright   (C) 2026 Magnus Hasselquist
 * @license     GPL-2.0-or-later
 */

namespace Joomla\Plugin\System\HqOidc\Oidc;

\defined('_JEXEC') or die;

interface HttpClientInterface
{
    /**
     * @param array<string, string> $headers
     */
    public function get(string $url, array $headers = []): HttpResponse;

    /**
     * POST an application/x-www-form-urlencoded body.
     *
     * @param array<string, string> $form
     * @param array<string, string> $headers
     */
    public function postForm(string $url, array $form, array $headers = []): HttpResponse;
}
