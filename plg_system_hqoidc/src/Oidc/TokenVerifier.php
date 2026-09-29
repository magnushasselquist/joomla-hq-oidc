<?php
/**
 * @package     plg_system_hqoidc
 * @copyright   (C) 2026 Magnus Hasselquist
 * @license     GPL-2.0-or-later
 */

namespace Joomla\Plugin\System\HqOidc\Oidc;

\defined('_JEXEC') or die;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;

/**
 * ID token validation per OIDC Core 3.1.3.7. Signature and time checks are
 * delegated to firebase/php-jwt; issuer, audience, azp, nonce and required
 * claims are checked here.
 */
final class TokenVerifier
{
    /**
     * Asymmetric algorithms only, and only those firebase/php-jwt verifies
     * with ext-openssl. PS* would need phpseclib; EdDSA would need ext-sodium.
     */
    public const ALLOWED_ALGS = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384'];

    private const KTY_FOR_ALG_PREFIX = ['RS' => 'RSA', 'ES' => 'EC'];

    public function __construct(
        private readonly string $issuer,
        private readonly string $clientId,
        private readonly int $leewaySeconds = 60,
    ) {
    }

    /**
     * @param array<string, mixed> $jwks The provider's JWKS document
     *
     * @return array<string, mixed> The verified claims
     */
    public function verify(#[\SensitiveParameter] string $idToken, array $jwks, ?string $expectedNonce): array
    {
        $header = self::header($idToken);
        $alg    = $header['alg'] ?? null;

        if (!\is_string($alg) || !\in_array($alg, self::ALLOWED_ALGS, true)) {
            throw new OidcException(sprintf(
                'ID token is signed with %s, which is not supported.'
                . ' Configure the client at the IdP for RS256 (the default) or ES256.',
                \is_string($alg) && $alg !== '' ? self::logSafe($alg) : 'an unspecified algorithm'
            ));
        }

        $kid = $header['kid'] ?? null;

        if (!\is_string($kid) || $kid === '') {
            throw new OidcException('ID token header has no "kid"; cannot select a signing key');
        }

        $keys = $this->signingKeys($jwks, $kid, $alg);

        $previousLeeway = JWT::$leeway;
        JWT::$leeway    = $this->leewaySeconds;

        try {
            $payload = JWT::decode($idToken, $keys);
        } catch (ExpiredException $e) {
            throw new OidcException('ID token has expired', 0, $e);
        } catch (BeforeValidException $e) {
            throw new OidcException('ID token is not valid yet (check the server clock)', 0, $e);
        } catch (SignatureInvalidException $e) {
            throw new OidcException('ID token signature verification failed', 0, $e);
        } catch (\UnexpectedValueException | \DomainException | \InvalidArgumentException $e) {
            throw new OidcException('ID token is malformed: ' . $e->getMessage(), 0, $e);
        } finally {
            JWT::$leeway = $previousLeeway;
        }

        $claims = json_decode(json_encode($payload, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);

        foreach (['sub', 'exp', 'iat'] as $required) {
            if (!isset($claims[$required]) || $claims[$required] === '') {
                throw new OidcException(sprintf('ID token has no "%s" claim', $required));
            }
        }

        if (!\is_string($claims['sub'])) {
            throw new OidcException('ID token "sub" claim is not a string');
        }

        $this->checkIssuer($claims);
        $this->checkAudience($claims);
        $this->checkNonce($claims, $expectedNonce);

        return $claims;
    }

    /**
     * @return array<string, mixed>
     */
    private static function header(string $jwt): array
    {
        $segments = explode('.', $jwt);

        if (\count($segments) !== 3) {
            throw new OidcException('ID token is not a compact JWS (expected three segments)');
        }

        $header = json_decode(JWT::urlsafeB64Decode($segments[0]), true);

        if (!\is_array($header)) {
            throw new OidcException('ID token header is not a JSON object');
        }

        return $header;
    }

    /**
     * Narrow the JWKS to signature keys matching the token's kid and key type
     * before handing it to firebase, so a key of the wrong type or use can
     * never be selected.
     *
     * @param array<string, mixed> $jwks
     *
     * @return array<string, \Firebase\JWT\Key>
     */
    private function signingKeys(array $jwks, string $kid, string $alg): array
    {
        $kty        = self::KTY_FOR_ALG_PREFIX[substr($alg, 0, 2)];
        $candidates = [];

        foreach ($jwks['keys'] ?? [] as $jwk) {
            if (!\is_array($jwk) || ($jwk['kid'] ?? null) !== $kid || ($jwk['kty'] ?? null) !== $kty) {
                continue;
            }

            if (($jwk['use'] ?? 'sig') !== 'sig' || (isset($jwk['alg']) && $jwk['alg'] !== $alg)) {
                continue;
            }

            $candidates[] = $jwk;
        }

        if ($candidates === []) {
            throw new OidcException(sprintf(
                'No %s signing key with kid "%s" in the provider JWKS (key rotation in progress?)',
                $alg,
                self::logSafe($kid)
            ));
        }

        try {
            return JWK::parseKeySet(['keys' => $candidates], $alg);
        } catch (\UnexpectedValueException | \DomainException | \InvalidArgumentException $e) {
            throw new OidcException('Provider JWKS is malformed: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function checkIssuer(array $claims): void
    {
        $iss = $claims['iss'] ?? null;

        if (!\is_string($iss)) {
            throw new OidcException('ID token has no "iss" claim');
        }

        // Google documents "accounts.google.com" without scheme as a valid iss.
        $accepted = [$this->issuer];

        if ($this->issuer === 'https://accounts.google.com') {
            $accepted[] = 'accounts.google.com';
        }

        if (!\in_array($iss, $accepted, true)) {
            throw new OidcException(sprintf(
                'ID token issuer "%s" does not match the provider issuer "%s"',
                self::logSafe($iss),
                $this->issuer
            ));
        }
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function checkAudience(array $claims): void
    {
        $aud       = $claims['aud'] ?? null;
        $audiences = \is_string($aud) ? [$aud] : (\is_array($aud) ? array_values(array_filter($aud, 'is_string')) : []);

        if (!\in_array($this->clientId, $audiences, true)) {
            throw new OidcException('ID token audience does not include this client');
        }

        $azp = $claims['azp'] ?? null;

        if (\count($audiences) > 1 && $azp === null) {
            throw new OidcException('ID token has multiple audiences but no "azp" claim');
        }

        if ($azp !== null && $azp !== $this->clientId) {
            throw new OidcException('ID token "azp" claim does not match this client');
        }
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function checkNonce(array $claims, ?string $expectedNonce): void
    {
        if ($expectedNonce === null) {
            return;
        }

        $nonce = $claims['nonce'] ?? null;

        if (!\is_string($nonce) || !hash_equals($expectedNonce, $nonce)) {
            throw new OidcException('ID token nonce does not match the authorization request');
        }
    }

    private static function logSafe(string $value): string
    {
        return substr(preg_replace('/[\x00-\x1F\x7F]+/', ' ', $value) ?? '', 0, 200);
    }
}
