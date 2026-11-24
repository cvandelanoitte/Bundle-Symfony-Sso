<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Tests\Unit\User;

use Issl\SsoBundle\User\RoleMapper;
use PHPUnit\Framework\TestCase;

final class RoleMapperTest extends TestCase
{
    private const array MAP = ['user' => 'ROLE_USER', 'admin' => 'ROLE_SUPER_ADMIN'];

    public function testMapsTheKeycloakClientRolesOfThisAppOnly(): void
    {
        $mapper = new RoleMapper('resource_access.{client_id}.roles', 'cooking', self::MAP);

        $roles = $mapper->map([
            'resource_access' => [
                'cooking' => ['roles' => ['admin', 'user', 'unknown']],
                'finance' => ['roles' => ['admin']],
            ],
        ]);

        self::assertSame(['ROLE_SUPER_ADMIN', 'ROLE_USER'], $roles);
    }

    public function testRoleOfAnotherAppGivesNoAccess(): void
    {
        $mapper = new RoleMapper('resource_access.{client_id}.roles', 'cooking', self::MAP);

        self::assertSame([], $mapper->map(['resource_access' => ['finance' => ['roles' => ['user']]]]));
        self::assertSame([], $mapper->map([]));
        self::assertSame([], $mapper->map(['resource_access' => 'garbage']));
    }

    public function testReadsAWholeClaimNameAndObjectRolesLikeZitadel(): void
    {
        $mapper = new RoleMapper('urn:zitadel:iam:org:project:roles', 'cooking', self::MAP);

        $roles = $mapper->map(['urn:zitadel:iam:org:project:roles' => ['admin' => ['org-id' => 'example.com']]]);

        self::assertSame(['ROLE_SUPER_ADMIN'], $roles);
    }

    public function testAcceptsASingleStringRoleAndDeduplicates(): void
    {
        $mapper = new RoleMapper('app_roles', 'cooking', ['user' => 'ROLE_USER', 'member' => 'ROLE_USER']);

        self::assertSame(['ROLE_USER'], $mapper->map(['app_roles' => 'user']));
        self::assertSame(['ROLE_USER'], $mapper->map(['app_roles' => ['user', 'member', 42]]));
    }
}
