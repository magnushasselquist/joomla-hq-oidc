<?php
/**
 * @package     plg_system_hqoidc
 * @copyright   (C) 2026 Magnus Hasselquist
 * @license     GPL-2.0-or-later
 */

namespace Joomla\Plugin\System\HqOidc\Oidc;

\defined('_JEXEC') or die;

/**
 * The subset of the OpenID Provider Metadata (OIDC Discovery 1.0, section 3)
 * that the plugin needs.
 */
final class Discovery
{
    private const WELL_KNOWN_PATH = '/.well-known/openid-configuration';

    /**
     * @param string[] $tokenEndpointAuthMethods
     */
    public function __construct(
        public readonly string $issuer,
        public readonly string $authorizationEndpoint,
        public readonly string $tokenEndpoint,
        public readonly string $jwksUri,
        public readonly ?string $userinfoEndpoint,
        public readonly ?string $endSessionEndpoint,
        public readonly array $tokenEndpointAuthMethods,
    ) {
    }

    public static function fetch(HttpClientInterface $http, string $issuerUrl): self
    {
        $url      = rtrim($issuerUrl, '/') . self::WELL_KNOWN_PATH;
        $response = $http->get($url, ['Accept' => 'application/json']);

        if ($response->status !== 200) {
            throw new OidcException(sprintf('Discovery request to %s returned HTTP %d', $url, $response->status));
        }

        return self::fromJson($response->body, $issuerUrl);
    }

    public static function fromJson(string $json, string $expectedIssuer): self
    {
        $doc = json_decode($json, true);

        if (!\is_array($doc)) {
            throw new OidcException('Discovery document is not a JSON object');
        }

        foreach (['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $field) {
            if (!isset($doc[$field]) || !\is_string($doc[$field]) || $doc[$field] === '') {
                throw new OidcException(sprintf('Discovery document lacks required field "%s"', $field));
            }
        }

        $issuer = $doc['issuer'];

        // Discovery 4.3: the issuer in the document must match the URL we
        // derived it from. Trailing-slash differences are tolerated because
        // some providers (Auth0) include one in their issuer identifier; the
        // document's exact value is what ID tokens will carry in "iss".
        if (rtrim($issuer, '/') !== rtrim($expectedIssuer, '/')) {
            $hint = str_contains($issuer, '{tenantid}')
                ? ' Microsoft Entra ID: use the tenant-specific issuer URL'
                    . ' (https://login.microsoftonline.com/<tenant-id>/v2.0), not /common.'
                : '';

            throw new OidcException(sprintf(
                'Discovery issuer "%s" does not match the configured issuer URL "%s".%s',
                $issuer,
                $expectedIssuer,
                $hint
            ));
        }

        // RFC 8414 / Discovery 3: absent means client_secret_basic only.
        $methods = $doc['token_endpoint_auth_methods_supported'] ?? null;
        $methods = \is_array($methods)
            ? array_values(array_filter($methods, 'is_string'))
            : ['client_secret_basic'];

        return new self(
            $issuer,
            $doc['authorization_endpoint'],
            $doc['token_endpoint'],
            $doc['jwks_uri'],
            self::optionalUrl($doc, 'userinfo_endpoint'),
            self::optionalUrl($doc, 'end_session_endpoint'),
            $methods
        );
    }

    /**
     * @param array<string, mixed> $doc
     */
    private static function optionalUrl(array $doc, string $field): ?string
    {
        $value = $doc[$field] ?? null;

        return \is_string($value) && $value !== '' ? $value : null;
    }
}
