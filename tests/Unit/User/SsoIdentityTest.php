<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Tests\Unit\User;

use Issl\SsoBundle\User\RoleMapper;
use Issl\SsoBundle\User\SsoIdentity;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SsoIdentityTest extends TestCase
{
    public function testBuildsFromStandardClaims(): void
    {
        $identity = SsoIdentity::fromClaims([
            'sub' => 'abc',
            'email' => 'Alice@Example.com',
            'email_verified' => true,
            'preferred_username' => 'alice',
            'given_name' => 'Alice',
            'family_name' => 'Martin',
            'resource_access' => ['cooking' => ['roles' => ['user']]],
        ], $this->mapper());

        self::assertSame('abc', $identity->subject);
        self::assertSame('Alice@Example.com', $identity->verifiedEmail());
        self::assertSame('alice', $identity->username);
        self::assertSame('Alice Martin', $identity->name);
        self::assertSame(['ROLE_USER'], $identity->roles);
        self::assertTrue($identity->hasRole('ROLE_USER'));
        self::assertFalse($identity->hasRole('ROLE_SUPER_ADMIN'));
    }

    /**
     * @return iterable<string, array{mixed, bool}>
     */
    public static function emailVerifiedValues(): iterable
    {
        yield 'true' => [true, true];
        yield 'string true' => ['true', true];
        yield 'false' => [false, false];
        yield 'string false' => ['false', false];
        yield 'missing' => [null, false];
        yield 'garbage' => ['yes please', false];
    }

    #[DataProvider('emailVerifiedValues')]
    public function testAnUnverifiedEmailIsNeverOfferedForLinking(mixed $value, bool $verified): void
    {
        $identity = SsoIdentity::fromClaims(['sub' => 'abc', 'email' => 'a@example.com', 'email_verified' => $value], $this->mapper());

        self::assertSame($verified, $identity->emailVerified);
        self::assertSame($verified ? 'a@example.com' : null, $identity->verifiedEmail());
    }

    public function testRequiresASubject(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        SsoIdentity::fromClaims(['email' => 'a@example.com'], $this->mapper());
    }

    private function mapper(): RoleMapper
    {
        return new RoleMapper('resource_access.{client_id}.roles', 'cooking', ['user' => 'ROLE_USER']);
    }
}
