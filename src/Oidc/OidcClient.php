<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Oidc;

use Issl\SsoBundle\Oidc\Exception\OidcException;
use Jose\Component\Core\JWKSet;
use Psr\Clock\ClockInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpClientException;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Talks to the identity provider: discovery, signing keys, authorization URL,
 * code exchange and end of session.
 *
 * Two base URLs, because the browser and the app may not reach the provider the
 * same way:
 * - $issuer:       the public URL (https://auth.example.com/realms/x). It is the
 *                  "iss" of the tokens and the origin of the browser redirects.
 * - $discoveryUri: where this server fetches the discovery document; by default
 *                  the issuer. Behind Docker it can be an internal URL
 *                  (http://keycloak:8080/realms/x): with Keycloak's
 *                  "hostname-backchannel-dynamic", the server-to-server endpoints
 *                  it announces (token, keys) then stay on that internal URL,
 *                  while the browser endpoints keep the public one.
 *
 * Stateless (safe under long-running workers): everything it remembers lives
 * in the cache.
 */
final readonly class OidcClient
{
    private const int METADATA_TTL = 3600;
    private const int JWKS_TTL = 3600;
    /** A token signed with an unknown key forces a key refresh at most this often. */
    private const int JWKS_MIN_REFRESH_INTERVAL = 60;

    public function __construct(
        private HttpClientInterface $httpClient,
        private CacheInterface $cache,
        private ClockInterface $clock,
        private string $issuer,
        private string $discoveryUri,
        private string $clientId,
        #[\SensitiveParameter]
        private string $clientSecret,
    ) {
    }

    public function getIssuer(): string
    {
        return $this->issuer;
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function getMetadata(): ProviderMetadata
    {
        return $this->cache->get($this->cacheKey('metadata'), function (ItemInterface $item): ProviderMetadata {
            $item->expiresAfter(self::METADATA_TTL);
            $metadata = ProviderMetadata::fromDiscoveryDocument(
                $this->requestJson('GET', rtrim($this->discoveryUri, '/').'/.well-known/openid-configuration'),
            );
            if ($metadata->issuer !== $this->issuer) {
                throw new OidcException(\sprintf('The identity provider announced the issuer "%s", "%s" is expected: check the issuer setting.', $metadata->issuer, $this->issuer));
            }

            return $metadata;
        });
    }

    /**
     * The provider's signature keys. $refresh re-downloads them (a token signed
     * with a key not seen yet, after a key rotation), but at most once a minute
     * so that forged tokens cannot make every request hit the provider.
     */
    public function getSigningKeys(bool $refresh = false): JWKSet
    {
        $beta = null;
        if ($refresh) {
            $now = $this->clock->now()->getTimestamp();
            $lastRefresh = $this->cache->get($this->cacheKey('jwks_refreshed_at'), static fn (): int => 0);
            if ($now - $lastRefresh >= self::JWKS_MIN_REFRESH_INTERVAL) {
                $this->cache->get($this->cacheKey('jwks_refreshed_at'), static fn (): int => $now, \INF);
                $beta = \INF;
            }
        }

        /** @var list<array<string, mixed>> $keys */
        $keys = $this->cache->get($this->cacheKey('jwks'), function (ItemInterface $item): array {
            $item->expiresAfter(self::JWKS_TTL);
            $document = $this->requestJson('GET', $this->getMetadata()->jwksUri);
            $keys = $document['keys'] ?? null;
            if (!\is_array($keys)) {
                throw new OidcException('The JWKS document has no "keys".');
            }

            return self::signatureKeys($keys);
        }, $beta);

        return JWKSet::createFromKeyData(['keys' => $keys]);
    }

    /**
     * @param list<string> $scopes
     */
    public function createAuthorizationUrl(AuthorizationRequest $authorization, string $redirectUri, array $scopes, ?string $prompt = null): string
    {
        $query = [
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $redirectUri,
            'scope' => implode(' ', $scopes),
            'state' => $authorization->state,
            'nonce' => $authorization->nonce,
            'code_challenge' => $authorization->codeChallenge(),
            'code_challenge_method' => 'S256',
        ];
        if (null !== $prompt) {
            $query['prompt'] = $prompt;
        }

        return self::appendQuery($this->getMetadata()->authorizationEndpoint, $query);
    }

    public function exchangeAuthorizationCode(string $code, string $codeVerifier, string $redirectUri): TokenResponse
    {
        return TokenResponse::fromArray($this->requestJson('POST', $this->getMetadata()->tokenEndpoint, [
            // client_secret_post: no Basic-auth encoding rules to get wrong.
            'body' => [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $redirectUri,
                'code_verifier' => $codeVerifier,
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
            ],
        ]));
    }

    /**
     * URL that ends the provider session (RP-initiated logout), or null when the
     * provider does not support it.
     */
    public function createEndSessionUrl(?string $idTokenHint, string $postLogoutRedirectUri): ?string
    {
        $endpoint = $this->getMetadata()->endSessionEndpoint;
        if (null === $endpoint) {
            return null;
        }
        $query = ['client_id' => $this->clientId, 'post_logout_redirect_uri' => $postLogoutRedirectUri];
        if (null !== $idTokenHint) {
            $query['id_token_hint'] = $idTokenHint;
        }

        return self::appendQuery($endpoint, $query);
    }

    /**
     * @param array<string, mixed> $options
     *
     * @return array<mixed>
     */
    private function requestJson(string $method, string $url, array $options = []): array
    {
        try {
            $response = $this->httpClient->request($method, $url, $options + ['timeout' => 10, 'max_redirects' => 0]);
            $status = $response->getStatusCode();
            $content = $response->getContent(false);
        } catch (HttpClientException $e) {
            throw new OidcException(\sprintf('The identity provider could not be reached (%s %s): %s', $method, $url, $e->getMessage()), 0, $e);
        }
        $data = json_decode($content, true);
        if ($status >= 300) {
            $error = \is_array($data) && \is_string($data['error'] ?? null) ? $data['error'] : 'no error code';
            $description = \is_array($data) && \is_string($data['error_description'] ?? null) ? ': '.$data['error_description'] : '';

            throw new OidcException(\sprintf('%s %s returned HTTP %d (%s%s).', $method, $url, $status, $error, $description));
        }
        if (!\is_array($data)) {
            throw new OidcException(\sprintf('%s %s did not return a JSON object.', $method, $url));
        }

        return $data;
    }

    /**
     * Keeps the keys meant for signatures; Keycloak also publishes an encryption
     * key ("use": "enc") that must never verify a signature.
     *
     * @param array<mixed> $keys
     *
     * @return list<array<string, mixed>>
     */
    private static function signatureKeys(array $keys): array
    {
        $signatureKeys = [];
        foreach ($keys as $key) {
            if (!\is_array($key) || 'enc' === ($key['use'] ?? null)) {
                continue;
            }
            /** @var array<string, mixed> $signatureKey */
            $signatureKey = $key;
            $signatureKeys[] = $signatureKey;
        }

        return $signatureKeys;
    }

    /**
     * @param array<string, string> $query
     */
    private static function appendQuery(string $url, array $query): string
    {
        return $url.(str_contains($url, '?') ? '&' : '?').http_build_query($query, '', '&', \PHP_QUERY_RFC3986);
    }

    private function cacheKey(string $name): string
    {
        // Cache keys may not contain "{}()/\@:", hence the hash.
        return 'issl_sso.'.$name.'.'.hash('xxh128', $this->discoveryUri.'|'.$this->issuer);
    }
}
