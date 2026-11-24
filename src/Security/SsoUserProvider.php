<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Security;

use Issl\SsoBundle\Security\Exception\SsoAuthenticationException;
use Issl\SsoBundle\User\RoleMapper;
use Issl\SsoBundle\User\SsoIdentity;
use Issl\SsoBundle\User\SsoUserManagerInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\AttributesBasedUserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * User provider of the bearer-token API firewall ("access_token" with the
 * "oidc" token handler): Symfony validates the access token, then hands its
 * claims here, and the app's SsoUserManagerInterface returns the local user.
 *
 * Stateless firewalls only: a session firewall keeps the app's own (entity)
 * provider, which reloads the user by its id on each request.
 *
 * @implements AttributesBasedUserProviderInterface<UserInterface>
 */
final readonly class SsoUserProvider implements AttributesBasedUserProviderInterface
{
    /**
     * @param class-string $userClass
     */
    public function __construct(
        private SsoUserManagerInterface $userManager,
        private RoleMapper $roleMapper,
        private string $userClass,
        private bool $requireRole = true,
    ) {
    }

    /**
     * @param array<string, mixed> $attributes the claims of the validated token
     */
    public function loadUserByIdentifier(string $identifier, array $attributes = []): UserInterface
    {
        // Only the claims of a token Symfony has just validated are trusted.
        if (($attributes['sub'] ?? null) !== $identifier) {
            $exception = new UserNotFoundException('SSO users are loaded from the claims of a validated token only.');
            $exception->setUserIdentifier($identifier);

            throw $exception;
        }
        $identity = SsoIdentity::fromClaims($attributes, $this->roleMapper);
        if ($this->requireRole && [] === $identity->roles) {
            throw SsoAuthenticationException::pending();
        }

        return $this->userManager->provision($identity);
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        throw new UnsupportedUserException(\sprintf('"%s" serves stateless firewalls only: give the session firewall the app\'s own user provider.', self::class));
    }

    public function supportsClass(string $class): bool
    {
        return is_a($class, $this->userClass, true);
    }
}
