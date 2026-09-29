<?php
/**
 * @package     plg_system_hqoidc
 * @copyright   (C) 2026 Magnus Hasselquist
 * @license     GPL-2.0-or-later
 */

namespace Joomla\Plugin\System\HqOidc\Tests\Oidc;

use Firebase\JWT\JWT;
use Joomla\Plugin\System\HqOidc\Oidc\OidcException;
use Joomla\Plugin\System\HqOidc\Oidc\TokenVerifier;
use PHPUnit\Framework\TestCase;

final class TokenVerifierTest extends TestCase
{
    private const ISSUER    = 'https://idp.example/realms/test';
    private const CLIENT_ID = 'joomla-site';
    private const NONCE     = 'n0nce';

    private static string $rsaPrivate;
    private static string $ecPrivate;

    /** @var array<string, mixed> */
    private static array $jwks;

    public static function setUpBeforeClass(): void
    {
        $rsa = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        $ec  = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);

        openssl_pkey_export($rsa, $rsaPem);
        openssl_pkey_export($ec, $ecPem);
        self::$rsaPrivate = $rsaPem;
        self::$ecPrivate  = $ecPem;

        $rsaDetails = openssl_pkey_get_details($rsa);
        $ecDetails  = openssl_pkey_get_details($ec);

        self::$jwks = ['keys' => [
            // Keycloak-style encryption key sharing nothing but the kty with the signing key.
            ['kty' => 'RSA', 'kid' => 'rsa-1', 'use' => 'enc', 'alg' => 'RSA-OAEP', 'n' => 'AA', 'e' => 'AQAB'],
            ['kty' => 'RSA', 'kid' => 'rsa-1', 'use' => 'sig', 'alg' => 'RS256', 'n' => self::b64url($rsaDetails['rsa']['n']), 'e' => self::b64url($rsaDetails['rsa']['e'])],
            ['kty' => 'EC', 'kid' => 'ec-1', 'use' => 'sig', 'crv' => 'P-256', 'x' => self::b64url($ecDetails['ec']['x']), 'y' => self::b64url($ecDetails['ec']['y'])],
        ]];
    }

    public function testVerifiesRs256TokenAndReturnsNestedClaimsAsArrays(): void
    {
        $claims = $this->verifier()->verify($this->token(['realm_access' => ['roles' => ['member']]]), self::$jwks, self::NONCE);

        self::assertSame('user-1', $claims['sub']);
        self::assertSame(self::ISSUER, $claims['iss']);
        self::assertSame(['member'], $claims['realm_access']['roles']);
    }

    public function testVerifiesEs256TokenUsingKeyWithoutAlgMember(): void
    {
        $token = JWT::encode($this->payload(), self::$ecPrivate, 'ES256', 'ec-1');

        self::assertSame('user-1', $this->verifier()->verify($token, self::$jwks, self::NONCE)['sub']);
    }

    public function testSymmetricAndNoneAlgorithmsAreRejectedBeforeSignatureCheck(): void
    {
        foreach (['HS256', 'none', 'PS256'] as $alg) {
            $token = self::b64url(json_encode(['alg' => $alg, 'kid' => 'rsa-1'])) . '.' . self::b64url(json_encode($this->payload())) . '.sig';

            try {
                $this->verifier()->verify($token, self::$jwks, self::NONCE);
                self::fail('Expected rejection of ' . $alg);
            } catch (OidcException $e) {
                self::assertStringContainsString('signed with ' . $alg, $e->getMessage());
                self::assertStringContainsString('RS256 (the default) or ES256', $e->getMessage());
            }
        }
    }

    public function testMissingKidIsRejected(): void
    {
        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('no "kid"');

        $this->verifier()->verify(JWT::encode($this->payload(), self::$rsaPrivate, 'RS256'), self::$jwks, self::NONCE);
    }

    public function testUnknownKidHintsAtKeyRotation(): void
    {
        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('No RS256 signing key with kid "rotated-away"');

        $this->verifier()->verify(JWT::encode($this->payload(), self::$rsaPrivate, 'RS256', 'rotated-away'), self::$jwks, self::NONCE);
    }

    public function testTamperedPayloadFailsSignatureCheck(): void
    {
        [$header, , $signature] = explode('.', $this->token());
        $tampered = $header . '.' . self::b64url(json_encode($this->payload(['sub' => 'admin']))) . '.' . $signature;

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('signature verification failed');

        $this->verifier()->verify($tampered, self::$jwks, self::NONCE);
    }

    public function testIssuerMismatchIsRejected(): void
    {
        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('issuer "https://evil.example" does not match');

        $this->verifier()->verify($this->token(['iss' => 'https://evil.example']), self::$jwks, self::NONCE);
    }

    public function testGoogleSchemelessIssuerIsAccepted(): void
    {
        $verifier = new TokenVerifier('https://accounts.google.com', self::CLIENT_ID);

        self::assertSame('accounts.google.com', $verifier->verify($this->token(['iss' => 'accounts.google.com']), self::$jwks, self::NONCE)['iss']);

        $this->expectException(OidcException::class);
        $this->verifier()->verify($this->token(['iss' => 'idp.example']), self::$jwks, self::NONCE);
    }

    public function testAudienceRules(): void
    {
        $verifier = $this->verifier();

        self::assertSame(
            'user-1',
            $verifier->verify($this->token(['aud' => ['other', self::CLIENT_ID], 'azp' => self::CLIENT_ID]), self::$jwks, self::NONCE)['sub']
        );

        $cases = [
            'audience does not include this client' => ['aud' => 'other'],
            'multiple audiences but no "azp"'       => ['aud' => ['other', self::CLIENT_ID]],
            '"azp" claim does not match'            => ['aud' => self::CLIENT_ID, 'azp' => 'other'],
        ];

        foreach ($cases as $expectedMessage => $overrides) {
            try {
                $verifier->verify($this->token($overrides), self::$jwks, self::NONCE);
                self::fail('Expected rejection: ' . $expectedMessage);
            } catch (OidcException $e) {
                self::assertStringContainsString($expectedMessage, $e->getMessage());
            }
        }
    }

    public function testNonceRules(): void
    {
        $verifier = $this->verifier();

        self::assertSame('user-1', $verifier->verify($this->token(['nonce' => null]), self::$jwks, null)['sub']);

        foreach ([['nonce' => 'other'], ['nonce' => null]] as $overrides) {
            try {
                $verifier->verify($this->token($overrides), self::$jwks, self::NONCE);
                self::fail('Expected nonce rejection');
            } catch (OidcException $e) {
                self::assertStringContainsString('nonce does not match', $e->getMessage());
            }
        }
    }

    public function testExpiryHonoursLeewayAndRestoresGlobalSetting(): void
    {
        JWT::$leeway = 7;

        $verifier = new TokenVerifier(self::ISSUER, self::CLIENT_ID, 60);

        self::assertSame('user-1', $verifier->verify($this->token(['exp' => time() - 30]), self::$jwks, self::NONCE)['sub']);
        self::assertSame(7, JWT::$leeway);

        try {
            $verifier->verify($this->token(['exp' => time() - 120]), self::$jwks, self::NONCE);
            self::fail('Expected expiry rejection');
        } catch (OidcException $e) {
            self::assertSame('ID token has expired', $e->getMessage());
        }

        self::assertSame(7, JWT::$leeway);
        JWT::$leeway = 0;
    }

    public function testRequiredClaimsAreEnforced(): void
    {
        foreach (['sub', 'exp', 'iat'] as $claim) {
            try {
                $this->verifier()->verify($this->token([$claim => null]), self::$jwks, self::NONCE);
                self::fail('Expected rejection for missing ' . $claim);
            } catch (OidcException $e) {
                self::assertSame(sprintf('ID token has no "%s" claim', $claim), $e->getMessage());
            }
        }
    }

    public function testGarbageIsRejectedWithoutTouchingKeys(): void
    {
        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('three segments');

        $this->verifier()->verify('not-a-jwt', ['keys' => []], self::NONCE);
    }

    private function verifier(): TokenVerifier
    {
        return new TokenVerifier(self::ISSUER, self::CLIENT_ID);
    }

    /**
     * @param array<string, mixed> $overrides Null removes the claim.
     */
    private function token(array $overrides = []): string
    {
        return JWT::encode($this->payload($overrides), self::$rsaPrivate, 'RS256', 'rsa-1');
    }

    /**
     * @param array<string, mixed> $overrides Null removes the claim.
     *
     * @return array<string, mixed>
     */
    private function payload(array $overrides = []): array
    {
        $claims = array_merge([
            'iss'   => self::ISSUER,
            'sub'   => 'user-1',
            'aud'   => self::CLIENT_ID,
            'exp'   => time() + 300,
            'iat'   => time(),
            'nonce' => self::NONCE,
        ], $overrides);

        return array_filter($claims, static fn ($v) => $v !== null);
    }

    private static function b64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
