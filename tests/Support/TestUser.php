<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Tests\Support;

use Symfony\Component\Security\Core\User\UserInterface;

final class TestUser implements UserInterface
{
    /**
     * @param list<string> $roles
     */
    public function __construct(
        public ?string $ssoSubject,
        public string $email,
        public ?string $username = null,
        public array $roles = [],
    ) {
    }

    /**
     * @return non-empty-string
     */
    public function getUserIdentifier(): string
    {
        $identifier = $this->ssoSubject ?? $this->email;

        return '' !== $identifier ? $identifier : 'anonymous';
    }

    public function getRoles(): array
    {
        return $this->roles;
    }

    public function eraseCredentials(): void
    {
    }
}
