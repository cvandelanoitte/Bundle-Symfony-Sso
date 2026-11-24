<?php

declare(strict_types=1);

namespace Issl\SsoBundle\User;

/**
 * Turns the roles the identity provider gives the user FOR THIS APP into
 * Symfony roles.
 *
 * With Keycloak, a client role "admin" of the client "cooking" arrives as
 * {"resource_access": {"cooking": {"roles": ["admin"]}}}: the claim path is
 * "resource_access.{client_id}.roles" and the map {admin: ROLE_SUPER_ADMIN}.
 * Provider roles missing from the map are ignored, so a role meant for another
 * app never leaks into this one.
 */
final readonly class RoleMapper
{
    /**
     * @param string                $claimPath dot-separated path; "{client_id}" is replaced by $clientId
     * @param array<string, string> $map       provider role => Symfony role
     */
    public function __construct(
        private string $claimPath,
        private string $clientId,
        private array $map,
    ) {
    }

    /**
     * @param array<string, mixed> $claims
     *
     * @return list<string> the Symfony roles, empty when the user has no access to this app
     */
    public function map(array $claims): array
    {
        $roles = [];
        foreach ($this->providerRoles($claims) as $providerRole) {
            if (isset($this->map[$providerRole])) {
                $roles[] = $this->map[$providerRole];
            }
        }

        return array_values(array_unique($roles));
    }

    /**
     * @param array<string, mixed> $claims
     *
     * @return list<string> the roles as the provider names them
     */
    public function providerRoles(array $claims): array
    {
        $path = str_replace('{client_id}', $this->clientId, $this->claimPath);
        // A claim name can itself contain dots or colons
        // ("urn:zitadel:iam:org:project:roles"): try it whole first.
        $value = \array_key_exists($path, $claims) ? $claims[$path] : $this->resolvePath($claims, explode('.', $path));

        if (\is_string($value)) {
            return [$value];
        }
        if (!\is_array($value)) {
            return [];
        }
        // A list (Keycloak) holds the roles; an object (Zitadel) has them as keys.
        $roles = array_is_list($value) ? $value : array_keys($value);

        return array_values(array_filter($roles, \is_string(...)));
    }

    /**
     * @param list<string> $segments
     */
    private function resolvePath(mixed $value, array $segments): mixed
    {
        foreach ($segments as $segment) {
            if (!\is_array($value) || !\array_key_exists($segment, $value)) {
                return null;
            }
            $value = $value[$segment];
        }

        return $value;
    }
}
