<?php
/**
 * @package     plg_system_hqoidc
 * @copyright   (C) 2026 Magnus Hasselquist
 * @license     GPL-2.0-or-later
 */

namespace Joomla\Plugin\System\HqOidc\Tests\Oidc;

use Joomla\Plugin\System\HqOidc\Oidc\Client;
use Joomla\Plugin\System\HqOidc\Oidc\Discovery;
use Joomla\Plugin\System\HqOidc\Oidc\OidcException;
use Joomla\Plugin\System\HqOidc\Tests\Support\FakeHttpClient;
use Joomla\Plugin\System\HqOidc\Tests\Support\Fixtures;
use PHPUnit\Framework\TestCase;

final class ClientTest extends TestCase
{
    private const CLIENT_ID    = 'joomla-site';
    private const SECRET       = 'sh=hh sec/ret';
    private const REDIRECT_URI = 'https://site.example/index.php?option=hqoidc&task=callback';

    public function testRandomTokenIsAValidPkceVerifier(): void
    {
        $token = Client::randomToken();

        self::assertSame(43, \strlen($token));
        self::assertMatchesRegularExpression('/^[A-Za-z0-9._~-]+$/', $token);
        self::assertNotSame($token, Client::randomToken());
    }

    public function testAuthorizationUrlCarriesCodeFlowAndS256Challenge(): void
    {
        $client = $this->client(new FakeHttpClient(), Fixtures::keycloak(), self::SECRET, ['openid', 'profile', 'email']);

        $url = $client->authorizationUrl('the-state', 'the-nonce', 'the-verifier');

        [$base, $query] = explode('?', $url, 2);
        parse_str($query, $params);

        self::assertSame(Fixtures::keycloak()->authorizationEndpoint, $base);
        self::assertSame('code', $params['response_type']);
        self::assertSame(self::CLIENT_ID, $params['client_id']);
        self::assertSame(self::REDIRECT_URI, $params['redirect_uri']);
        self::assertSame('openid profile email', $params['scope']);
        self::assertSame('the-state', $params['state']);
        self::assertSame('the-nonce', $params['nonce']);
        self::assertSame('S256', $params['code_challenge_method']);
        self::assertSame(
            rtrim(strtr(base64_encode(hash('sha256', 'the-verifier', true)), '+/', '-_'), '='),
            $params['code_challenge']
        );
    }

    public function testOpenidScopeIsAlwaysRequestedAndExistingQueryIsExtended(): void
    {
        $discovery = new Discovery('https://idp.example', 'https://idp.example/auth?tenant=x', 'https://idp.example/token', 'https://idp.example/jwks', null, null, ['client_secret_basic']);
        $client    = $this->client(new FakeHttpClient(), $discovery, null, ['email']);

        $url = $client->authorizationUrl('s', 'n', 'v');

        self::assertStringStartsWith('https://idp.example/auth?tenant=x&response_type=code', $url);
        parse_str(explode('?', $url, 2)[1], $params);
        self::assertSame('openid email', $params['scope']);
    }

    public function testExchangeCodePrefersBasicAuth(): void
    {
        $http = new FakeHttpClient();
        $http->on('POST', Fixtures::keycloak()->tokenEndpoint, 200, json_encode(['id_token' => 'x.y.z', 'access_token' => 'at', 'token_type' => 'Bearer']));

        $tokens = $this->client($http, Fixtures::keycloak(), self::SECRET)->exchangeCode('the-code', 'the-verifier');

        self::assertSame('x.y.z', $tokens['id_token']);

        $request = $http->lastRequest();
        self::assertSame('Basic ' . base64_encode(urlencode(self::CLIENT_ID) . ':' . urlencode(self::SECRET)), $request['headers']['Authorization']);
        self::assertSame([
            'grant_type'    => 'authorization_code',
            'code'          => 'the-code',
            'redirect_uri'  => self::REDIRECT_URI,
            'client_id'     => self::CLIENT_ID,
            'code_verifier' => 'the-verifier',
        ], $request['form']);
    }

    public function testExchangeCodeFallsBackToPostWhenProviderOnlySupportsPost(): void
    {
        $discovery = new Discovery('https://idp.example', 'https://idp.example/auth', 'https://idp.example/token', 'https://idp.example/jwks', null, null, ['client_secret_post']);
        $http      = new FakeHttpClient();
        $http->on('POST', 'https://idp.example/token', 200, json_encode(['id_token' => 'x.y.z']));

        $this->client($http, $discovery, self::SECRET)->exchangeCode('c', 'v');

        $request = $http->lastRequest();
        self::assertArrayNotHasKey('Authorization', $request['headers']);
        self::assertSame(self::SECRET, $request['form']['client_secret']);
    }

    public function testPublicClientSendsNoCredentials(): void
    {
        $http = new FakeHttpClient();
        $http->on('POST', Fixtures::keycloak()->tokenEndpoint, 200, json_encode(['id_token' => 'x.y.z']));

        $this->client($http, Fixtures::keycloak(), null)->exchangeCode('c', 'v');

        $request = $http->lastRequest();
        self::assertArrayNotHasKey('Authorization', $request['headers']);
        self::assertArrayNotHasKey('client_secret', $request['form']);
    }

    public function testTokenErrorIsSurfacedWithoutControlCharacters(): void
    {
        $http = new FakeHttpClient();
        $http->on('POST', Fixtures::keycloak()->tokenEndpoint, 400, json_encode([
            'error'             => 'invalid_grant',
            'error_description' => "Code not valid\r\nInjected: line",
        ]));

        try {
            $this->client($http, Fixtures::keycloak(), self::SECRET)->exchangeCode('c', 'v');
            self::fail('Expected OidcException');
        } catch (OidcException $e) {
            self::assertSame('Token endpoint returned HTTP 400: invalid_grant (Code not valid Injected: line)', $e->getMessage());
        }
    }

    public function testTokenResponseWithoutIdTokenIsRejected(): void
    {
        $http = new FakeHttpClient();
        $http->on('POST', Fixtures::keycloak()->tokenEndpoint, 200, json_encode(['access_token' => 'at']));

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('no id_token');

        $this->client($http, Fixtures::keycloak(), self::SECRET)->exchangeCode('c', 'v');
    }

    public function testFetchJwksRequiresKeysArray(): void
    {
        $http = new FakeHttpClient();
        $http->on('GET', Fixtures::keycloak()->jwksUri, 200, json_encode(['keys' => [['kid' => 'a']]]));

        self::assertSame([['kid' => 'a']], $this->client($http, Fixtures::keycloak(), null)->fetchJwks()['keys']);

        $http->on('GET', Fixtures::keycloak()->jwksUri, 200, json_encode(['nope' => true]));

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('"keys"');

        $this->client($http, Fixtures::keycloak(), null)->fetchJwks();
    }

    public function testFetchUserinfoSendsBearerToken(): void
    {
        $http = new FakeHttpClient();
        $http->on('GET', Fixtures::keycloak()->userinfoEndpoint, 200, json_encode(['sub' => '42', 'email' => 'a@b.example']));

        $claims = $this->client($http, Fixtures::keycloak(), null)->fetchUserinfo('the-access-token');

        self::assertSame('a@b.example', $claims['email']);
        self::assertSame('Bearer the-access-token', $http->lastRequest()['headers']['Authorization']);
    }

    public function testFetchUserinfoIsNullWithoutEndpointAndRejectsSignedResponses(): void
    {
        $noUserinfo = new Discovery('https://idp.example', 'https://idp.example/auth', 'https://idp.example/token', 'https://idp.example/jwks', null, null, []);
        self::assertNull($this->client(new FakeHttpClient(), $noUserinfo, null)->fetchUserinfo('t'));

        $http = new FakeHttpClient();
        $http->on('GET', Fixtures::keycloak()->userinfoEndpoint, 200, 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI0MiJ9.c2ln');

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('signed JWT');

        $this->client($http, Fixtures::keycloak(), null)->fetchUserinfo('t');
    }

    public function testEndSessionUrl(): void
    {
        $url = $this->client(new FakeHttpClient(), Fixtures::keycloak(), null)->endSessionUrl('id.tok.en', 'https://site.example/');

        [$base, $query] = explode('?', $url, 2);
        parse_str($query, $params);

        self::assertSame(Fixtures::keycloak()->endSessionEndpoint, $base);
        self::assertSame('id.tok.en', $params['id_token_hint']);
        self::assertSame('https://site.example/', $params['post_logout_redirect_uri']);
        self::assertSame(self::CLIENT_ID, $params['client_id']);

        self::assertNull($this->client(new FakeHttpClient(), Fixtures::google(), null)->endSessionUrl('t', 'https://site.example/'));
    }

    /**
     * @param string[] $scopes
     */
    private function client(FakeHttpClient $http, Discovery $discovery, ?string $secret, array $scopes = ['openid']): Client
    {
        return new Client($http, $discovery, self::CLIENT_ID, $secret, self::REDIRECT_URI, $scopes);
    }
}
