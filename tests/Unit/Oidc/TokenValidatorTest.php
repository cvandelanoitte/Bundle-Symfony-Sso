<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Tests\Unit\Oidc;

use Issl\SsoBundle\Oidc\AuthorizationRequest;
use Issl\SsoBundle\Oidc\Exception\OidcException;
use Issl\SsoBundle\Oidc\OidcClient;
use Issl\SsoBundle\Oidc\TokenValidator;
use Issl\SsoBundle\Tests\Support\TestIdentityProvider;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Clock\MockClock;

final class TokenValidatorTest extends TestCase
{
    private const int NOW = 1_800_000_000;

    private TestIdentityProvider $provider;
    private TokenValidator $validator;

    protected function setUp(): void
    {
        $this->provider = new TestIdentityProvider();
        $clock = new MockClock('@'.self::NOW);
        $client = new OidcClient($this->provider->httpClient(), new ArrayAdapter(), $clock, TestIdentityProvider::ISSUER, TestIdentityProvider::INTERNAL_URI, TestIdentityProvider::CLIENT_ID, TestIdentityProvider::CLIENT_SECRET);
        $this->validator = new TokenValidator($client, $clock, 30);
    }

    public function testAcceptsAValidToken(): void
    {
        $claims = $this->validator->validateIdToken(TestIdentityProvider::sign($this->claims()), 'the-nonce');

        self::assertSame('alice@example.com', $claims['email']);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function invalidClaims(): iterable
    {
        yield 'other nonce' => [['nonce' => 'another-nonce'], 'nonce'];
        yield 'no nonce' => [['nonce' => null], 'nonce'];
        yield 'other issuer' => [['iss' => 'https://evil.test/realms/issl'], 'not valid'];
        yield 'other audience' => [['aud' => 'finance', 'azp' => 'finance'], 'not valid'];
        yield 'issued to another client' => [['aud' => ['cooking', 'finance'], 'azp' => 'finance'], 'issued to "finance"'];
        yield 'several audiences without azp' => [['aud' => ['cooking', 'finance'], 'azp' => null], 'not to this client'];
        yield 'expired beyond the leeway' => [['exp' => self::NOW - 31], 'not valid'];
        yield 'issued in the future' => [['iat' => self::NOW + 60], 'not valid'];
        yield 'not before' => [['nbf' => self::NOW + 60], 'not valid'];
        yield 'empty subject' => [['sub' => ''], 'sub'];
        yield 'no subject' => [['sub' => null], 'not valid'];
    }

    /**
     * @param array<string, mixed> $overrides
     */
    #[DataProvider('invalidClaims')]
    public function testRejectsInvalidClaims(array $overrides, string $message): void
    {
        $claims = array_filter(array_merge($this->claims(), $overrides), static fn (mixed $value): bool => null !== $value);

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage($message);

        $this->validator->validateIdToken(TestIdentityProvider::sign($claims), 'the-nonce');
    }

    public function testToleratesTheClockSkewLeeway(): void
    {
        $claims = $this->validator->validateIdToken(TestIdentityProvider::sign(['exp' => self::NOW - 20, 'iat' => self::NOW + 20] + $this->claims()), 'the-nonce');

        self::assertSame(TestIdentityProvider::ISSUER, $claims['iss']);
    }

    public function testRejectsATokenSignedWithAnotherKey(): void
    {
        $forged = TestIdentityProvider::sign($this->claims(), JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'kid' => 'test-key']));

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('signature');

        $this->validator->validateIdToken($forged, 'the-nonce');
    }

    public function testRejectsUnsignedAndSymmetricTokens(): void
    {
        $payload = AuthorizationRequest::base64UrlEncode(json_encode($this->claims(), \JSON_THROW_ON_ERROR));
        foreach (['none', 'HS256'] as $algorithm) {
            $header = AuthorizationRequest::base64UrlEncode(json_encode(['alg' => $algorithm, 'typ' => 'JWT'], \JSON_THROW_ON_ERROR));
            try {
                $this->validator->validateIdToken($header.'.'.$payload.'.'.AuthorizationRequest::base64UrlEncode('sig'), 'the-nonce');
                self::fail(\sprintf('A token signed with "%s" was accepted.', $algorithm));
            } catch (OidcException $e) {
                self::assertStringContainsString('not accepted', $e->getMessage());
            }
        }
    }

    public function testFetchesTheKeysAgainAfterARotation(): void
    {
        $this->validator->validateIdToken(TestIdentityProvider::sign($this->claims()), 'the-nonce');
        $newKey = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig', 'kid' => 'rotated-key']);
        /** @var array<string, mixed> $publicKey */
        $publicKey = $newKey->toPublic()->all();
        $this->provider->servedKeys = [$publicKey];

        $claims = $this->validator->validateIdToken(TestIdentityProvider::sign($this->claims(), $newKey), 'the-nonce');

        self::assertSame(TestIdentityProvider::ISSUER, $claims['iss']);
        self::assertSame(2, $this->provider->jwksDownloads);
    }

    public function testAcceptsAnAccessTokenOfAnotherClientForThisApp(): void
    {
        // A mobile app or a script asks the token; this app is in its audience.
        $claims = $this->validator->validateAccessToken(TestIdentityProvider::sign(
            ['aud' => ['cooking', 'account'], 'azp' => 'cooking-mobile', 'typ' => 'Bearer', 'nonce' => null] + $this->claims(),
        ));

        self::assertSame('cooking-mobile', $claims['azp']);
    }

    public function testRejectsAnAccessTokenForAnotherApp(): void
    {
        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('not valid');

        $this->validator->validateAccessToken(TestIdentityProvider::sign(['aud' => ['finance', 'account'], 'typ' => 'Bearer'] + $this->claims()));
    }

    public function testAnIdTokenIsNotAnAccessToken(): void
    {
        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('"ID" token is not an access token');

        $this->validator->validateAccessToken(TestIdentityProvider::sign(['typ' => 'ID'] + $this->claims()));
    }

    public function testRejectsGarbage(): void
    {
        $this->expectException(OidcException::class);

        $this->validator->validateIdToken('not-a-jwt', 'the-nonce');
    }

    /**
     * @return array<string, mixed>
     */
    private function claims(): array
    {
        return TestIdentityProvider::claims(['nonce' => 'the-nonce'], self::NOW);
    }
}
