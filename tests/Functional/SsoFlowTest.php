<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Tests\Functional;

use Issl\SsoBundle\Tests\Support\TestIdentityProvider;
use Issl\SsoBundle\Tests\Support\TestKernel;
use Issl\SsoBundle\Tests\Support\TestLoginRecorder;
use Issl\SsoBundle\Tests\Support\TestUser;
use Issl\SsoBundle\Tests\Support\TestUserManager;
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Clock\Test\ClockSensitiveTrait;

/**
 * The whole browser and API flows, against a fake provider.
 */
final class SsoFlowTest extends WebTestCase
{
    use ClockSensitiveTrait;

    private const int NOW = 1_800_000_000;

    private KernelBrowser $browser;
    private TestIdentityProvider $provider;
    private TestUserManager $users;

    protected static function getKernelClass(): string
    {
        return TestKernel::class;
    }

    protected function setUp(): void
    {
        self::mockTime('@'.self::NOW);
        $this->browser = self::createClient();
        $this->browser->disableReboot();
        $container = self::getContainer();
        /** @var TestIdentityProvider $provider */
        $provider = $container->get('test.identity_provider');
        /** @var TestUserManager $users */
        $users = $container->get(TestUserManager::class);
        $this->provider = $provider;
        $this->users = $users;
    }

    public function testSignsInThroughTheProviderAndReturnsToTheRequestedPage(): void
    {
        $this->browser->request('GET', '/admin');
        self::assertResponseRedirects('/oidc/connect');

        $this->browser->followRedirect();
        $authorize = $this->authorizationQuery();
        self::assertSame('code', $authorize['response_type']);
        self::assertSame('cooking', $authorize['client_id']);
        self::assertSame('https://cooking.test/oidc/callback', $authorize['redirect_uri']);
        self::assertSame('openid profile email', $authorize['scope']);
        self::assertSame('S256', $authorize['code_challenge_method']);
        self::assertArrayNotHasKey('prompt', $authorize);

        $this->provider->nextIdTokenClaims = $this->claims($authorize, ['user', 'admin']);
        $this->browser->request('GET', '/oidc/callback', ['code' => 'the-code', 'state' => $authorize['state']]);

        self::assertResponseRedirects('http://localhost/admin');
        $tokenRequests = array_values(array_filter($this->provider->requests, static fn (array $request): bool => 'POST' === $request['method']));
        self::assertCount(1, $tokenRequests);
        parse_str($tokenRequests[0]['body'], $tokenRequest);
        self::assertSame('the-code', $tokenRequest['code']);
        self::assertIsString($tokenRequest['code_verifier']);
        self::assertSame(
            $authorize['code_challenge'],
            rtrim(strtr(base64_encode(hash('sha256', $tokenRequest['code_verifier'], true)), '+/', '-_'), '='),
            'the verifier sent to the token endpoint must match the challenge of the authorization request',
        );

        $this->browser->followRedirect();
        self::assertResponseIsSuccessful();
        self::assertSame('Admin area', $this->browser->getResponse()->getContent());
        self::assertCount(1, $this->users->users);
        self::assertSame(['ROLE_USER', 'ROLE_SUPER_ADMIN'], $this->users->users[0]->roles);
        self::assertSame('alice', $this->users->users[0]->username);
    }

    public function testAnAccountWithoutRoleForThisAppGetsThePendingPage(): void
    {
        $this->startSignIn('/');
        $authorize = $this->authorizationQuery();
        $this->provider->nextIdTokenClaims = $this->claims($authorize, []);

        $this->browser->request('GET', '/oidc/callback', ['code' => 'c', 'state' => $authorize['state']]);

        self::assertResponseStatusCodeSame(403);
        self::assertSelectorTextContains('h1', 'Access pending');
        self::assertSelectorExists('a[href="/oidc/connect?prompt=login"]');
        self::assertSame(0, $this->users->provisionCount, 'no local user for an account without access');
        $this->browser->request('GET', '/');
        self::assertResponseRedirects('/oidc/connect');
    }

    public function testTheAppCanRefuseAnAccountWithItsOwnMessage(): void
    {
        $this->startSignIn('/');
        $authorize = $this->authorizationQuery();
        $this->provider->nextIdTokenClaims = ['email' => 'refused@example.com'] + $this->claims($authorize, ['user']);

        $this->browser->request('GET', '/oidc/callback', ['code' => 'c', 'state' => $authorize['state']]);

        self::assertResponseStatusCodeSame(401);
        self::assertSelectorTextContains('h1', 'Access refused');
        self::assertSelectorTextContains('p', 'This account is suspended here.');
        $this->browser->request('GET', '/');
        self::assertResponseRedirects('/oidc/connect');
    }

    public function testACallbackIsAcceptedOnlyOnceAndForItsOwnState(): void
    {
        $this->startSignIn('/');
        $authorize = $this->authorizationQuery();
        $this->provider->nextIdTokenClaims = $this->claims($authorize, ['user']);

        $this->browser->request('GET', '/oidc/callback', ['code' => 'c', 'state' => 'forged-state']);
        self::assertResponseStatusCodeSame(401);
        self::assertSelectorTextContains('p', 'Your sign-in request has expired.');

        $this->browser->request('GET', '/oidc/callback', ['code' => 'c', 'state' => $authorize['state']]);
        self::assertResponseRedirects('http://localhost/');
        $this->browser->request('GET', '/oidc/callback', ['code' => 'c', 'state' => $authorize['state']]);
        self::assertResponseStatusCodeSame(401, 'a replayed callback must fail');
    }

    public function testCancellingAtTheProvider(): void
    {
        $this->startSignIn('/');

        $this->browser->request('GET', '/oidc/callback', ['error' => 'access_denied', 'state' => $this->authorizationQuery()['state']]);

        self::assertResponseStatusCodeSame(401);
        self::assertSelectorTextContains('p', 'Sign-in was cancelled.');
    }

    public function testAnIdTokenForAnotherSignInIsRefused(): void
    {
        $this->startSignIn('/');
        $authorize = $this->authorizationQuery();
        $this->provider->nextIdTokenClaims = ['nonce' => 'another-nonce'] + $this->claims($authorize, ['user']);

        $this->browser->request('GET', '/oidc/callback', ['code' => 'c', 'state' => $authorize['state']]);

        self::assertResponseStatusCodeSame(401);
        self::assertSelectorTextContains('p', 'Sign-in failed.');
        self::assertSame(0, $this->users->provisionCount);
    }

    public function testLinksAnExistingAccountByVerifiedEmailOnly(): void
    {
        $existing = $this->users->users[] = new TestUser(null, 'alice@example.com', 'alice');
        $this->signIn(['user']);
        self::assertSame(TestIdentityProvider::claims()['sub'], $existing->ssoSubject);
        self::assertCount(1, $this->users->users);

        $this->browser->request('GET', '/logout');
        $this->users->users = [$other = new TestUser(null, 'bob@example.com', 'bob')];
        $this->signIn(['user'], ['sub' => 'mallory', 'email' => 'bob@example.com', 'email_verified' => false]);

        self::assertNull($other->ssoSubject, 'an unverified email must not take over an account');
        self::assertCount(2, $this->users->users);
    }

    public function testLogoutAlsoEndsTheProviderSession(): void
    {
        $this->signIn(['user']);
        $idToken = $this->lastIdToken();

        $this->browser->request('GET', '/logout');

        self::assertResponseRedirects(TestIdentityProvider::ISSUER.'/protocol/openid-connect/logout?client_id=cooking&post_logout_redirect_uri=https%3A%2F%2Fcooking.test%2F&id_token_hint='.$idToken);
        $this->browser->request('GET', '/');
        self::assertResponseRedirects('/oidc/connect');
    }

    public function testRevalidatesTheSessionSilentlyEveryHour(): void
    {
        $this->signIn(['user']);
        $this->browser->request('GET', '/');
        self::assertResponseIsSuccessful();

        self::mockTime('@'.(self::NOW + 3601));
        $this->browser->request('GET', '/');
        self::assertResponseRedirects('/oidc/connect?prompt=none&_target_path=/');

        $this->browser->followRedirect();
        $authorize = $this->authorizationQuery();
        self::assertSame('none', $authorize['prompt']);

        // The provider session is alive and the account now is an admin.
        $this->provider->nextIdTokenClaims = $this->claims($authorize, ['user', 'admin'], self::NOW + 3601);
        $this->browser->request('GET', '/oidc/callback', ['code' => 'c2', 'state' => $authorize['state']]);
        self::assertResponseRedirects('http://localhost/');
        $this->browser->request('GET', '/admin');
        self::assertResponseIsSuccessful('the roles are refreshed by the silent check');
        $this->browser->request('GET', '/');
        self::assertResponseIsSuccessful('no new check before another hour');
        /** @var TestLoginRecorder $logins */
        $logins = self::getContainer()->get(TestLoginRecorder::class);
        self::assertSame([false, true], $logins->silentChecks, 'one sign-in, then one silent check');
    }

    public function testASilentCheckFailingAtTheProviderSignsTheUserOut(): void
    {
        $this->signIn(['user']);
        self::mockTime('@'.(self::NOW + 3601));
        $this->browser->request('GET', '/');
        $this->browser->followRedirect();
        $authorize = $this->authorizationQuery();

        $this->browser->request('GET', '/oidc/callback', ['error' => 'login_required', 'state' => $authorize['state']]);

        self::assertResponseRedirects('/oidc/connect?_target_path=/');
        $this->browser->followRedirect();
        self::assertArrayNotHasKey('prompt', $this->authorizationQuery(), 'the user signs in again, interactively');
    }

    public function testASilentCheckRevokesALostAccess(): void
    {
        $this->signIn(['user']);
        self::mockTime('@'.(self::NOW + 3601));
        $this->browser->request('GET', '/');
        $this->browser->followRedirect();
        $authorize = $this->authorizationQuery();
        $this->provider->nextIdTokenClaims = $this->claims($authorize, [], self::NOW + 3601);

        $this->browser->request('GET', '/oidc/callback', ['code' => 'c', 'state' => $authorize['state']]);

        self::assertResponseStatusCodeSame(403);
        $this->browser->request('GET', '/');
        self::assertResponseRedirects('/oidc/connect', null, 'the local session is gone');
    }

    public function testIgnoresATargetPathOutsideTheApp(): void
    {
        $this->browser->request('GET', '/oidc/connect', ['_target_path' => '//evil.test/']);
        $authorize = $this->authorizationQuery();
        $this->provider->nextIdTokenClaims = $this->claims($authorize, ['user']);

        $this->browser->request('GET', '/oidc/callback', ['code' => 'c', 'state' => $authorize['state']]);

        self::assertResponseRedirects('http://localhost/');
    }

    public function testAnApiCallWithoutTokenGetsAJson401(): void
    {
        $this->browser->request('GET', '/', [], [], ['HTTP_ACCEPT' => 'application/json']);

        self::assertResponseStatusCodeSame(401);
        self::assertJsonStringEqualsJsonString('{"error":"authentication_required"}', (string) $this->browser->getResponse()->getContent());
    }

    public function testTheApiAcceptsAProviderAccessTokenForThisApp(): void
    {
        $token = TestIdentityProvider::sign(['aud' => ['cooking', 'account']] + TestIdentityProvider::claims(now: self::NOW));

        $this->browser->request('GET', '/api/me', [], [], ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);

        self::assertResponseIsSuccessful();
        self::assertJsonStringEqualsJsonString(
            json_encode(['subject' => TestIdentityProvider::claims()['sub'], 'email' => 'alice@example.com', 'roles' => ['ROLE_USER']], \JSON_THROW_ON_ERROR),
            (string) $this->browser->getResponse()->getContent(),
        );
    }

    public function testTheApiFollowsAKeyRotationAtTheProvider(): void
    {
        $this->browser->request('GET', '/api/me', [], [], ['HTTP_AUTHORIZATION' => 'Bearer '.TestIdentityProvider::sign(['aud' => 'cooking'] + TestIdentityProvider::claims(now: self::NOW))]);
        self::assertResponseIsSuccessful();
        // The provider rotates its signing key; the app has the old one in cache.
        $newKey = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig', 'kid' => 'rotated-key']);
        /** @var array<string, mixed> $publicKey */
        $publicKey = $newKey->toPublic()->all();
        $this->provider->servedKeys = [$publicKey];

        $this->browser->request('GET', '/api/me', [], [], ['HTTP_AUTHORIZATION' => 'Bearer '.TestIdentityProvider::sign(['aud' => 'cooking'] + TestIdentityProvider::claims(now: self::NOW), $newKey)]);

        self::assertResponseIsSuccessful();
    }

    public function testTheApiRefusesAnIdToken(): void
    {
        $this->browser->request('GET', '/api/me', [], [], ['HTTP_AUTHORIZATION' => 'Bearer '.TestIdentityProvider::sign(['typ' => 'ID'] + TestIdentityProvider::claims(now: self::NOW))]);

        self::assertResponseStatusCodeSame(401);
    }

    public function testTheApiRefusesATokenForAnotherApp(): void
    {
        $token = TestIdentityProvider::sign(['aud' => ['finance', 'account']] + TestIdentityProvider::claims(now: self::NOW));

        $this->browser->request('GET', '/api/me', [], [], ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);

        self::assertResponseStatusCodeSame(401);
    }

    public function testTheApiRefusesAnAccountWithoutRole(): void
    {
        $token = TestIdentityProvider::sign(['aud' => ['cooking'], 'resource_access' => []] + TestIdentityProvider::claims(now: self::NOW));

        $this->browser->request('GET', '/api/me', [], [], ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);

        self::assertResponseStatusCodeSame(401);
        self::assertSame(0, $this->users->provisionCount);
    }

    /**
     * @param list<string>         $roles
     * @param array<string, mixed> $overrides
     */
    private function signIn(array $roles, array $overrides = []): void
    {
        $this->startSignIn('/');
        $authorize = $this->authorizationQuery();
        $this->provider->nextIdTokenClaims = $overrides + $this->claims($authorize, $roles);
        $this->browser->request('GET', '/oidc/callback', ['code' => 'c', 'state' => $authorize['state']]);
        self::assertResponseRedirects();
    }

    private function startSignIn(string $path): void
    {
        $this->browser->request('GET', $path);
        $this->browser->followRedirect();
    }

    /**
     * @return array<string, string> the query of the redirect to the provider
     */
    private function authorizationQuery(): array
    {
        $location = (string) $this->browser->getResponse()->headers->get('Location');
        self::assertStringStartsWith(TestIdentityProvider::ISSUER.'/protocol/openid-connect/auth?', $location);
        parse_str((string) parse_url($location, \PHP_URL_QUERY), $query);
        /** @var array<string, string> $authorize */
        $authorize = $query;

        return $authorize;
    }

    /**
     * @param array<string, string> $authorize
     * @param list<string>          $roles
     *
     * @return array<string, mixed>
     */
    private function claims(array $authorize, array $roles, int $now = self::NOW): array
    {
        return TestIdentityProvider::claims([
            'nonce' => $authorize['nonce'],
            'resource_access' => [TestIdentityProvider::CLIENT_ID => ['roles' => $roles]],
        ], $now);
    }

    private function lastIdToken(): string
    {
        return TestIdentityProvider::sign($this->provider->nextIdTokenClaims ?? []);
    }
}
