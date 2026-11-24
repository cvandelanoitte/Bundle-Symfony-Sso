<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Tests\Support;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\ResponseInterface;

/**
 * A fake OpenID provider behind a MockHttpClient: discovery, keys and token
 * endpoint, with tokens signed by a key generated for the test run.
 */
final class TestIdentityProvider
{
    public const string ISSUER = 'https://auth.test/realms/issl';
    public const string INTERNAL_URI = 'http://keycloak:8080/realms/issl';
    public const string CLIENT_ID = 'cooking';
    public const string CLIENT_SECRET = 'test-secret';

    private static ?JWK $key = null;

    /** @var list<array{method: string, url: string, body: string}> */
    public array $requests = [];
    /** @var array<string, mixed>|null claims of the ID token the token endpoint returns next */
    public ?array $nextIdTokenClaims = null;
    /** @var array{status: int, body: array<string, mixed>}|null */
    public ?array $tokenEndpointError = null;
    public int $jwksDownloads = 0;
    /** @var list<array<string, mixed>>|null public keys served instead of the test key */
    public ?array $servedKeys = null;

    public static function key(): JWK
    {
        return self::$key ??= JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig', 'kid' => 'test-key']);
    }

    /**
     * @param array<string, mixed> $claims
     */
    public static function sign(array $claims, ?JWK $key = null, string $algorithm = 'RS256'): string
    {
        $key ??= self::key();
        $jws = (new JWSBuilder(new AlgorithmManager([new RS256()])))
            ->create()
            ->withPayload(json_encode($claims, \JSON_THROW_ON_ERROR))
            ->addSignature($key, ['alg' => $algorithm, 'kid' => $key->has('kid') ? $key->get('kid') : 'none', 'typ' => 'JWT'])
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }

    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    public static function claims(array $overrides = [], int $now = 1_800_000_000): array
    {
        return $overrides + [
            'iss' => self::ISSUER,
            'sub' => 'f3c1a2b4-0000-4000-8000-000000000001',
            'aud' => self::CLIENT_ID,
            'azp' => self::CLIENT_ID,
            'iat' => $now,
            'exp' => $now + 300,
            'email' => 'alice@example.com',
            'email_verified' => true,
            'preferred_username' => 'alice',
            'name' => 'Alice Martin',
            'resource_access' => [self::CLIENT_ID => ['roles' => ['user']], 'account' => ['roles' => ['manage-account']]],
        ];
    }

    public function httpClient(): MockHttpClient
    {
        return new MockHttpClient($this);
    }

    /**
     * MockHttpClient response factory (also framework.http_client.mock_response_factory).
     *
     * @param array<string, mixed> $options
     */
    public function __invoke(string $method, string $url, array $options = []): ResponseInterface
    {
        $body = $options['body'] ?? '';
        $this->requests[] = ['method' => $method, 'url' => $url, 'body' => \is_string($body) ? $body : ''];

        return match (strtok($url, '?')) {
            self::INTERNAL_URI.'/.well-known/openid-configuration', self::ISSUER.'/.well-known/openid-configuration' => self::json([
                'issuer' => self::ISSUER,
                // Keycloak behind Docker with "hostname-backchannel-dynamic": browser
                // endpoints on the public URL, server-to-server ones on the internal URL.
                'authorization_endpoint' => self::ISSUER.'/protocol/openid-connect/auth',
                'end_session_endpoint' => self::ISSUER.'/protocol/openid-connect/logout',
                'token_endpoint' => self::INTERNAL_URI.'/protocol/openid-connect/token',
                'jwks_uri' => self::INTERNAL_URI.'/protocol/openid-connect/certs',
            ]),
            self::INTERNAL_URI.'/protocol/openid-connect/certs' => $this->jwks(),
            self::INTERNAL_URI.'/protocol/openid-connect/token' => $this->token(),
            default => new MockResponse('{"error":"not_found"}', ['http_code' => 404]),
        };
    }

    private function jwks(): MockResponse
    {
        ++$this->jwksDownloads;
        $keys = $this->servedKeys ?? [
            self::key()->toPublic()->all(),
            // Keycloak also publishes an encryption key: never valid for signatures.
            ['kty' => 'RSA', 'use' => 'enc', 'kid' => 'enc-key', 'alg' => 'RSA-OAEP', 'n' => 'AQAB', 'e' => 'AQAB'],
        ];

        return self::json(['keys' => $keys]);
    }

    private function token(): MockResponse
    {
        if (null !== $this->tokenEndpointError) {
            return self::json($this->tokenEndpointError['body'], $this->tokenEndpointError['status']);
        }
        $claims = $this->nextIdTokenClaims ?? self::claims();

        return self::json([
            'access_token' => self::sign(['aud' => 'account'] + $claims),
            'id_token' => self::sign($claims),
            'refresh_token' => 'refresh',
            'token_type' => 'Bearer',
            'expires_in' => 300,
        ]);
    }

    /**
     * @param array<mixed> $data
     */
    private static function json(array $data, int $status = 200): MockResponse
    {
        return new MockResponse(json_encode($data, \JSON_THROW_ON_ERROR), [
            'http_code' => $status,
            'response_headers' => ['content-type' => 'application/json'],
        ]);
    }
}
