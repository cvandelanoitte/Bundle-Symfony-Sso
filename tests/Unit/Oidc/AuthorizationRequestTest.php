<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Tests\Unit\Oidc;

use Issl\SsoBundle\Oidc\AuthorizationRequest;
use PHPUnit\Framework\TestCase;

final class AuthorizationRequestTest extends TestCase
{
    public function testCodeChallengeFollowsRfc7636(): void
    {
        // RFC 7636, appendix B.
        $request = new AuthorizationRequest('state', 'nonce', 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk', 0);

        self::assertSame('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', $request->codeChallenge());
    }

    public function testCreateGeneratesUnguessableUrlSafeSecrets(): void
    {
        $first = AuthorizationRequest::create(100, '/recipes');
        $second = AuthorizationRequest::create(100);

        self::assertNotSame($first->state, $second->state);
        self::assertNotSame($first->nonce, $second->nonce);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $first->state);
        // RFC 7636: 43 to 128 characters of [A-Za-z0-9-._~].
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43,128}$/', $first->codeVerifier);
        self::assertSame('/recipes', $first->targetPath);
        self::assertFalse($first->silent);
    }

    public function testRoundTripsThroughTheSession(): void
    {
        $request = AuthorizationRequest::create(1234, '/x', true);

        self::assertEquals($request, AuthorizationRequest::fromArray($request->toArray()));
    }

    public function testRejectsMalformedSessionData(): void
    {
        self::assertNull(AuthorizationRequest::fromArray('nope'));
        self::assertNull(AuthorizationRequest::fromArray(['state' => 's', 'nonce' => 'n']));
        self::assertNull(AuthorizationRequest::fromArray(['state' => 's', 'nonce' => 'n', 'code_verifier' => 'v', 'created_at' => '1']));
    }
}
