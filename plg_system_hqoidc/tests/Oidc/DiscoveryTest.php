<?php
/**
 * @package     plg_system_hqoidc
 * @copyright   (C) 2026 Magnus Hasselquist
 * @license     GPL-2.0-or-later
 */

namespace Joomla\Plugin\System\HqOidc\Tests\Oidc;

use Joomla\Plugin\System\HqOidc\Oidc\Discovery;
use Joomla\Plugin\System\HqOidc\Oidc\OidcException;
use Joomla\Plugin\System\HqOidc\Tests\Support\FakeHttpClient;
use Joomla\Plugin\System\HqOidc\Tests\Support\Fixtures;
use PHPUnit\Framework\TestCase;

final class DiscoveryTest extends TestCase
{
    public function testParsesKeycloakDocument(): void
    {
        $d = Fixtures::keycloak();

        self::assertSame(Fixtures::KEYCLOAK_ISSUER, $d->issuer);
        self::assertSame(Fixtures::KEYCLOAK_ISSUER . '/protocol/openid-connect/auth', $d->authorizationEndpoint);
        self::assertSame(Fixtures::KEYCLOAK_ISSUER . '/protocol/openid-connect/token', $d->tokenEndpoint);
        self::assertSame(Fixtures::KEYCLOAK_ISSUER . '/protocol/openid-connect/certs', $d->jwksUri);
        self::assertSame(Fixtures::KEYCLOAK_ISSUER . '/protocol/openid-connect/userinfo', $d->userinfoEndpoint);
        self::assertSame(Fixtures::KEYCLOAK_ISSUER . '/protocol/openid-connect/logout', $d->endSessionEndpoint);
        self::assertContains('client_secret_basic', $d->tokenEndpointAuthMethods);
        self::assertContains('client_secret_post', $d->tokenEndpointAuthMethods);
    }

    public function testGooglePublishesNoEndSessionEndpoint(): void
    {
        $d = Fixtures::google();

        self::assertNull($d->endSessionEndpoint);
        self::assertSame('https://openidconnect.googleapis.com/v1/userinfo', $d->userinfoEndpoint);
    }

    public function testEntraCommonEndpointIsRejectedWithTenantHint(): void
    {
        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('tenant-specific issuer URL');

        Discovery::fromJson(
            Fixtures::read('discovery-entra-common.json'),
            'https://login.microsoftonline.com/common/v2.0'
        );
    }

    public function testTrailingSlashDifferencesAreToleratedAndDocumentValueWins(): void
    {
        $withSlash = Discovery::fromJson(Fixtures::read('discovery-keycloak.json'), Fixtures::KEYCLOAK_ISSUER . '/');
        self::assertSame(Fixtures::KEYCLOAK_ISSUER, $withSlash->issuer);

        // Auth0-style: the provider's issuer identifier carries a trailing slash.
        $auth0 = Discovery::fromJson(self::minimalDocument(['issuer' => 'https://tenant.auth0.example/']), 'https://tenant.auth0.example');
        self::assertSame('https://tenant.auth0.example/', $auth0->issuer);
    }

    public function testDifferentIssuerIsRejected(): void
    {
        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('does not match the configured issuer URL');

        Discovery::fromJson(Fixtures::read('discovery-keycloak.json'), 'https://evil.example/realms/scoutnet');
    }

    public function testMissingRequiredFieldIsNamed(): void
    {
        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('"jwks_uri"');

        Discovery::fromJson(self::minimalDocument(['jwks_uri' => null]), 'https://idp.example');
    }

    public function testInvalidJsonIsRejected(): void
    {
        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('not a JSON object');

        Discovery::fromJson('<html>', 'https://idp.example');
    }

    public function testAuthMethodsDefaultToBasicWhenAbsent(): void
    {
        $d = Discovery::fromJson(self::minimalDocument(), 'https://idp.example');

        self::assertSame(['client_secret_basic'], $d->tokenEndpointAuthMethods);
        self::assertNull($d->userinfoEndpoint);
        self::assertNull($d->endSessionEndpoint);
    }

    public function testFetchUsesWellKnownPathAndRejectsNon200(): void
    {
        $http = new FakeHttpClient();
        $http->on('GET', Fixtures::KEYCLOAK_ISSUER . '/.well-known/openid-configuration', 200, Fixtures::read('discovery-keycloak.json'));

        $d = Discovery::fetch($http, Fixtures::KEYCLOAK_ISSUER . '/');

        self::assertSame(Fixtures::KEYCLOAK_ISSUER, $d->issuer);
        self::assertSame('application/json', $http->lastRequest()['headers']['Accept']);

        $http->on('GET', 'https://down.example/.well-known/openid-configuration', 503, '');

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('HTTP 503');

        Discovery::fetch($http, 'https://down.example');
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private static function minimalDocument(array $overrides = []): string
    {
        $doc = [
            'issuer'                 => 'https://idp.example',
            'authorization_endpoint' => 'https://idp.example/authorize',
            'token_endpoint'         => 'https://idp.example/token',
            'jwks_uri'               => 'https://idp.example/jwks',
        ];

        return json_encode(array_filter(array_merge($doc, $overrides), static fn ($v) => $v !== null), JSON_THROW_ON_ERROR);
    }
}
