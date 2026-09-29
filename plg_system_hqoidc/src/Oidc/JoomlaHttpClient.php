<?php
/**
 * @package     plg_system_hqoidc
 * @copyright   (C) 2026 Magnus Hasselquist
 * @license     GPL-2.0-or-later
 */

namespace Joomla\Plugin\System\HqOidc\Oidc;

\defined('_JEXEC') or die;

use Joomla\CMS\Http\HttpFactory;
use Joomla\Http\Http;

final class JoomlaHttpClient implements HttpClientInterface
{
    private const TIMEOUT_SECONDS = 15;

    public function __construct(private readonly Http $http)
    {
    }

    public static function create(): self
    {
        return new self(HttpFactory::getHttp());
    }

    public function get(string $url, array $headers = []): HttpResponse
    {
        $response = $this->http->get($url, $headers, self::TIMEOUT_SECONDS);

        return new HttpResponse($response->getStatusCode(), (string) $response->getBody());
    }

    public function postForm(string $url, array $form, array $headers = []): HttpResponse
    {
        // Joomla's transports form-encode array bodies and set the Content-Type.
        $response = $this->http->post($url, $form, $headers, self::TIMEOUT_SECONDS);

        return new HttpResponse($response->getStatusCode(), (string) $response->getBody());
    }
}
