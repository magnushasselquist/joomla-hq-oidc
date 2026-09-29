<?php
/**
 * @package     plg_system_hqoidc
 * @copyright   (C) 2026 Magnus Hasselquist
 * @license     GPL-2.0-or-later
 */

namespace Joomla\Plugin\System\HqOidc\Oidc;

\defined('_JEXEC') or die;

/**
 * Relying-party side of the authorization code flow with PKCE (OIDC Core 3.1,
 * RFC 7636) plus JWKS, userinfo and RP-initiated logout URL building.
 *
 * Holds no session state: callers keep state/nonce/verifier between the
 * authorization redirect and the callback.
 */
final class Client
{
    /**
     * @param string[] $scopes
     */
    public function __construct(
        private readonly HttpClientInterface $http,
        private readonly Discovery $discovery,
        private readonly string $clientId,
        #[\SensitiveParameter] private readonly ?string $clientSecret,
        private readonly string $redirectUri,
        private readonly array $scopes,
    ) {
    }

    /**
     * 32 random bytes, base64url: 43 chars from the unreserved set, which is
     * exactly what RFC 7636 4.1 requires of a code verifier. Also used for
     * state and nonce.
     */
    public static function randomToken(): string
    {
        return self::base64url(random_bytes(32));
    }

    public function authorizationUrl(string $state, string $nonce, string $codeVerifier): string
    {
        $scopes = $this->scopes;

        if (!\in_array('openid', $scopes, true)) {
            array_unshift($scopes, 'openid');
        }

        return self::appendQuery($this->discovery->authorizationEndpoint, [
            'response_type'         => 'code',
            'client_id'             => $this->clientId,
            'redirect_uri'          => $this->redirectUri,
            'scope'                 => implode(' ', $scopes),
            'state'                 => $state,
            'nonce'                 => $nonce,
            'code_challenge'        => self::base64url(hash('sha256', $codeVerifier, true)),
            'code_challenge_method' => 'S256',
        ]);
    }

    /**
     * @return array<string, mixed> The token response; id_token is guaranteed present.
     */
    public function exchangeCode(string $code, string $codeVerifier): array
    {
        $form = [
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'redirect_uri'  => $this->redirectUri,
            'client_id'     => $this->clientId,
            'code_verifier' => $codeVerifier,
        ];
        $headers = ['Accept' => 'application/json'];

        if ($this->clientSecret !== null && $this->clientSecret !== '') {
            if ($this->useBasicAuth()) {
                // RFC 6749 2.3.1: form-urlencode both parts before base64.
                $headers['Authorization'] = 'Basic ' . base64_encode(
                    urlencode($this->clientId) . ':' . urlencode($this->clientSecret)
                );
            } else {
                $form['client_secret'] = $this->clientSecret;
            }
        }

        $response = $this->http->postForm($this->discovery->tokenEndpoint, $form, $headers);
        $data     = json_decode($response->body, true);

        if ($response->status !== 200 || !\is_array($data)) {
            throw new OidcException(self::describeError('Token endpoint', $response, \is_array($data) ? $data : []));
        }

        if (!isset($data['id_token']) || !\is_string($data['id_token']) || $data['id_token'] === '') {
            throw new OidcException('Token response contains no id_token');
        }

        return $data;
    }

    /**
     * @return array<string, mixed> The JWKS document; "keys" is guaranteed to be an array.
     */
    public function fetchJwks(): array
    {
        $response = $this->http->get($this->discovery->jwksUri, ['Accept' => 'application/json']);

        if ($response->status !== 200) {
            throw new OidcException(sprintf('JWKS request returned HTTP %d', $response->status));
        }

        $jwks = $response->json('JWKS');

        if (!isset($jwks['keys']) || !\is_array($jwks['keys'])) {
            throw new OidcException('JWKS document has no "keys" array');
        }

        return $jwks;
    }

    /**
     * @return array<string, mixed>|null Null when the provider publishes no userinfo endpoint.
     */
    public function fetchUserinfo(#[\SensitiveParameter] string $accessToken): ?array
    {
        $endpoint = $this->discovery->userinfoEndpoint;

        if ($endpoint === null) {
            return null;
        }

        $response = $this->http->get($endpoint, [
            'Accept'        => 'application/json',
            'Authorization' => 'Bearer ' . $accessToken,
        ]);

        if ($response->status !== 200) {
            throw new OidcException(sprintf('Userinfo request returned HTTP %d', $response->status));
        }

        if (preg_match('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/', trim($response->body)) === 1) {
            throw new OidcException(
                'Userinfo response is a signed JWT (application/jwt), which is not supported;'
                . ' configure the client for unsigned userinfo responses'
            );
        }

        return $response->json('Userinfo');
    }

    /**
     * RP-initiated logout URL (OIDC RP-Initiated Logout 1.0, section 2), or
     * null when the provider publishes no end_session_endpoint.
     */
    public function endSessionUrl(#[\SensitiveParameter] string $idToken, string $postLogoutRedirectUri): ?string
    {
        $endpoint = $this->discovery->endSessionEndpoint;

        if ($endpoint === null) {
            return null;
        }

        return self::appendQuery($endpoint, [
            'id_token_hint'            => $idToken,
            'post_logout_redirect_uri' => $postLogoutRedirectUri,
            'client_id'                => $this->clientId,
        ]);
    }

    /**
     * Prefer client_secret_basic (the spec default), and only fall back to
     * client_secret_post when the provider advertises post but not basic.
     */
    private function useBasicAuth(): bool
    {
        $methods = $this->discovery->tokenEndpointAuthMethods;

        return \in_array('client_secret_basic', $methods, true)
            || !\in_array('client_secret_post', $methods, true);
    }

    /**
     * @param array<string, string> $params
     */
    private static function appendQuery(string $url, array $params): string
    {
        return $url
            . (str_contains($url, '?') ? '&' : '?')
            . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    private static function base64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function describeError(string $what, HttpResponse $response, array $data): string
    {
        $message = sprintf('%s returned HTTP %d', $what, $response->status);

        if (isset($data['error']) && \is_string($data['error'])) {
            $message .= ': ' . self::logSafe($data['error']);

            if (isset($data['error_description']) && \is_string($data['error_description'])) {
                $message .= ' (' . self::logSafe($data['error_description']) . ')';
            }
        }

        return $message;
    }

    private static function logSafe(string $value): string
    {
        return substr(preg_replace('/[\x00-\x1F\x7F]+/', ' ', $value) ?? '', 0, 200);
    }
}
