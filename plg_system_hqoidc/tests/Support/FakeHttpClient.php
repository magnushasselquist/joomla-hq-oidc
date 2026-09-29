<?php
/**
 * @package     plg_system_hqoidc
 * @copyright   (C) 2026 Magnus Hasselquist
 * @license     GPL-2.0-or-later
 */

namespace Joomla\Plugin\System\HqOidc\Tests\Support;

use Joomla\Plugin\System\HqOidc\Oidc\HttpClientInterface;
use Joomla\Plugin\System\HqOidc\Oidc\HttpResponse;

final class FakeHttpClient implements HttpClientInterface
{
    /** @var list<array{method: string, url: string, form: array<string, string>, headers: array<string, string>}> */
    public array $requests = [];

    /** @var array<string, HttpResponse> */
    private array $responses = [];

    public function on(string $method, string $url, int $status, string $body): void
    {
        $this->responses[$method . ' ' . $url] = new HttpResponse($status, $body);
    }

    public function get(string $url, array $headers = []): HttpResponse
    {
        return $this->respond('GET', $url, [], $headers);
    }

    public function postForm(string $url, array $form, array $headers = []): HttpResponse
    {
        return $this->respond('POST', $url, $form, $headers);
    }

    /**
     * @return array{method: string, url: string, form: array<string, string>, headers: array<string, string>}
     */
    public function lastRequest(): array
    {
        return $this->requests[array_key_last($this->requests)];
    }

    /**
     * @param array<string, string> $form
     * @param array<string, string> $headers
     */
    private function respond(string $method, string $url, array $form, array $headers): HttpResponse
    {
        $this->requests[] = compact('method', 'url', 'form', 'headers');

        $key = $method . ' ' . $url;

        if (!isset($this->responses[$key])) {
            throw new \LogicException('No fake response registered for ' . $key);
        }

        return $this->responses[$key];
    }
}
