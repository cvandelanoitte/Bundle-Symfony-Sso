<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Tests\Support;

use Issl\SsoBundle\User\SsoIdentity;
use Issl\SsoBundle\User\SsoUserManagerInterface;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAccountStatusException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * In-memory stand-in for an app's Doctrine user manager, following the
 * SsoUserManagerInterface contract; also the session firewall's user provider.
 *
 * @implements UserProviderInterface<TestUser>
 */
final class TestUserManager implements SsoUserManagerInterface, UserProviderInterface
{
    /** @var list<TestUser> */
    public array $users = [];
    public int $provisionCount = 0;

    public function provision(SsoIdentity $identity): UserInterface
    {
        ++$this->provisionCount;
        if ('refused@example.com' === $identity->email) {
            throw new CustomUserMessageAccountStatusException('This account is suspended here.');
        }
        $user = $this->findBySubject($identity->subject)
            ?? $this->findUnlinkedByEmail($identity->verifiedEmail())
            ?? $this->users[] = new TestUser(null, (string) $identity->email);

        $user->ssoSubject = $identity->subject;
        $user->email = (string) $identity->email;
        $user->username = $identity->username;
        $user->roles = $identity->roles;

        return $user;
    }

    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        return $this->findBySubject($identifier) ?? throw new UserNotFoundException();
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof TestUser) {
            throw new UnsupportedUserException();
        }

        return $this->loadUserByIdentifier($user->getUserIdentifier());
    }

    public function supportsClass(string $class): bool
    {
        return TestUser::class === $class;
    }

    private function findBySubject(string $subject): ?TestUser
    {
        foreach ($this->users as $user) {
            if ($user->ssoSubject === $subject) {
                return $user;
            }
        }

        return null;
    }

    private function findUnlinkedByEmail(?string $email): ?TestUser
    {
        foreach ($this->users as $user) {
            if (null !== $email && null === $user->ssoSubject && 0 === strcasecmp($user->email, $email)) {
                return $user;
            }
        }

        return null;
    }
}
