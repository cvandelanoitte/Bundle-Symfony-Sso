<?php

declare(strict_types=1);

namespace Issl\SsoBundle\User;

/**
 * Who signed in, as the identity provider vouches for it: the input of the
 * app's {@see SsoUserManagerInterface}.
 */
final readonly class SsoIdentity
{
    /**
     * @param non-empty-string     $subject       "sub": the stable, unique id of the account at the provider.
     *                                            Link local users with it, never with the email, which can change.
     * @param bool                 $emailVerified the provider checked that the user owns $email
     * @param list<string>         $roles         the Symfony roles for THIS app, from {@see RoleMapper}
     * @param array<string, mixed> $claims        every claim, for app-specific needs
     */
    public function __construct(
        public string $subject,
        public ?string $email,
        public bool $emailVerified,
        public ?string $username,
        public ?string $name,
        public array $roles,
        public array $claims,
    ) {
    }

    /**
     * @param array<string, mixed> $claims
     */
    public static function fromClaims(array $claims, RoleMapper $roleMapper): self
    {
        $subject = $claims['sub'] ?? null;
        if (!\is_string($subject) || '' === $subject) {
            throw new \InvalidArgumentException('The claims have no "sub".');
        }
        $name = self::stringClaim($claims, 'name')
            ?? self::nonEmpty(trim((self::stringClaim($claims, 'given_name') ?? '').' '.(self::stringClaim($claims, 'family_name') ?? '')));

        return new self(
            $subject,
            self::stringClaim($claims, 'email'),
            true === filter_var($claims['email_verified'] ?? false, \FILTER_VALIDATE_BOOL, \FILTER_NULL_ON_FAILURE),
            self::stringClaim($claims, 'preferred_username'),
            $name,
            $roleMapper->map($claims),
            $claims,
        );
    }

    public function hasRole(string $role): bool
    {
        return \in_array($role, $this->roles, true);
    }

    /**
     * The email, but only when the provider verified it: the one to use to link
     * an existing local account. An unverified email proves nothing, anyone can
     * sign up with someone else's address.
     */
    public function verifiedEmail(): ?string
    {
        return $this->emailVerified ? $this->email : null;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private static function stringClaim(array $claims, string $name): ?string
    {
        $value = $claims[$name] ?? null;

        return \is_string($value) ? self::nonEmpty(trim($value)) : null;
    }

    private static function nonEmpty(string $value): ?string
    {
        return '' === $value ? null : $value;
    }
}
