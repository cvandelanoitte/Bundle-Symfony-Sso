<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Tests\Unit\Oidc;

use Issl\SsoBundle\Oidc\AuthorizationRequest;
use Issl\SsoBundle\Oidc\Exception\OidcException;
use Issl\SsoBundle\Oidc\OidcClient;
use Issl\SsoBundle\Tests\Support\TestIdentityProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Clock\MockClock;

final class OidcClientTest extends TestCase
{
    private TestIdentityProvider $provider;
    private MockClock $clock;

    protected function setUp(): void
    {
        $this->provider = new TestIdentityProvider();
        $this->clock = new MockClock('@1800000000');
    }

    public function testReadsTheDiscoveryDocumentThroughTheInternalUrlOnce(): void
    {
        $client = $this->client();

        $metadata = $client->getMetadata();
        $client->getMetadata();

        self::assertSame(TestIdentityProvider::ISSUER.'/protocol/openid-connect/auth', $metadata->authorizationEndpoint);
        self::assertSame(TestIdentityProvider::INTERNAL_URI.'/protocol/openid-connect/token', $metadata->tokenEndpoint);
        self::assertCount(1, $this->provider->requests);
        self::assertSame(TestIdentityProvider::INTERNAL_URI.'/.well-known/openid-configuration', $this->provider->requests[0]['url']);
    }

    public function testRefusesAProviderAnnouncingAnotherIssuer(): void
    {
        $client = $this->client(issuer: 'https://evil.test/realms/issl');

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('announced the issuer');

        $client->getMetadata();
    }

    public function testBuildsTheAuthorizationUrl(): void
    {
        $authorization = AuthorizationRequest::create(1);

        $url = $this->client()->createAuthorizationUrl($authorization, 'https://cooking.test/oidc/callback', ['openid', 'email'], 'login');

        self::assertStringStartsWith(TestIdentityProvider::ISSUER.'/protocol/openid-connect/auth?', $url);
        parse_str((string) parse_url($url, \PHP_URL_QUERY), $query);
        self::assertSame([
            'response_type' => 'code',
            'client_id' => 'cooking',
            'redirect_uri' => 'https://cooking.test/oidc/callback',
            'scope' => 'openid email',
            'state' => $authorization->state,
            'nonce' => $authorization->nonce,
            'code_challenge' => $authorization->codeChallenge(),
            'code_challenge_method' => 'S256',
            'prompt' => 'login',
        ], $query);
        self::assertStringNotContainsString($authorization->codeVerifier, $url);
    }

    public function testExchangesTheCodeWithTheVerifierAndTheClientSecret(): void
    {
        $tokens = $this->client()->exchangeAuthorizationCode('the-code', 'the-verifier', 'https://cooking.test/oidc/callback');

        self::assertNotSame('', $tokens->idToken);
        self::assertSame('refresh', $tokens->refreshToken);
        self::assertSame(300, $tokens->expiresIn);
        $tokenRequest = $this->provider->requests[1];
        self::assertSame('POST', $tokenRequest['method']);
        self::assertSame(TestIdentityProvider::INTERNAL_URI.'/protocol/openid-connect/token', $tokenRequest['url']);
        parse_str($tokenRequest['body'], $body);
        self::assertSame([
            'grant_type' => 'authorization_code',
            'code' => 'the-code',
            'redirect_uri' => 'https://cooking.test/oidc/callback',
            'code_verifier' => 'the-verifier',
            'client_id' => 'cooking',
            'client_secret' => 'test-secret',
        ], $body);
    }

    public function testReportsTheProviderErrorOfARefusedCode(): void
    {
        $this->provider->tokenEndpointError = ['status' => 400, 'body' => ['error' => 'invalid_grant', 'error_description' => 'Code not valid']];

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('HTTP 400 (invalid_grant: Code not valid)');

        $this->client()->exchangeAuthorizationCode('used-code', 'verifier', 'https://cooking.test/oidc/callback');
    }

    public function testBuildsTheEndSessionUrl(): void
    {
        $url = $this->client()->createEndSessionUrl('id.token.hint', 'https://cooking.test/');

        self::assertSame(
            TestIdentityProvider::ISSUER.'/protocol/openid-connect/logout?client_id=cooking&post_logout_redirect_uri=https%3A%2F%2Fcooking.test%2F&id_token_hint=id.token.hint',
            $url,
        );
    }

    public function testKeepsOnlySignatureKeysAndRefreshesThemAtMostOnceAMinute(): void
    {
        $client = $this->client();

        $keys = $client->getSigningKeys();
        self::assertCount(1, $keys);
        self::assertTrue($keys->has('test-key'));
        self::assertFalse($keys->has('enc-key'));

        $client->getSigningKeys(refresh: true);
        $client->getSigningKeys(refresh: true);
        self::assertSame(2, $this->provider->jwksDownloads, 'the second forced refresh within a minute must be served from the cache');

        $this->clock->sleep(61);
        $client->getSigningKeys(refresh: true);
        self::assertSame(3, $this->provider->jwksDownloads);
    }

    public function testAnUnreachableProviderIsAnOidcException(): void
    {
        $client = $this->client(discoveryUri: 'http://nowhere.test/realms/issl');

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('HTTP 404');

        $client->getMetadata();
    }

    private function client(string $issuer = TestIdentityProvider::ISSUER, string $discoveryUri = TestIdentityProvider::INTERNAL_URI): OidcClient
    {
        return new OidcClient(
            $this->provider->httpClient(),
            new ArrayAdapter(),
            $this->clock,
            $issuer,
            $discoveryUri,
            TestIdentityProvider::CLIENT_ID,
            TestIdentityProvider::CLIENT_SECRET,
        );
    }
}
