<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Security;

use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * What the bundle keeps in the session of a user signed in through SSO: the ID
 * token (the hint for the provider logout) and the time of the last sign-in or
 * silent check (for the periodic revalidation).
 */
final readonly class SsoSession
{
    public const string ID_TOKEN = '_issl_sso.id_token';
    public const string AUTHENTICATED_AT = '_issl_sso.authenticated_at';

    public function __construct(
        private ClockInterface $clock,
    ) {
    }

    public function markAuthenticated(SessionInterface $session, ?string $idToken): void
    {
        if (null !== $idToken) {
            $session->set(self::ID_TOKEN, $idToken);
        }
        $session->set(self::AUTHENTICATED_AT, $this->clock->now()->getTimestamp());
    }

    /**
     * False for a user signed in some other way (a form login kept during a
     * migration, for instance).
     */
    public function isAuthenticated(SessionInterface $session): bool
    {
        return null !== $this->authenticatedAt($session);
    }

    public function authenticatedAt(SessionInterface $session): ?int
    {
        $authenticatedAt = $session->get(self::AUTHENTICATED_AT);

        return \is_int($authenticatedAt) ? $authenticatedAt : null;
    }

    public function idToken(SessionInterface $session): ?string
    {
        $idToken = $session->get(self::ID_TOKEN);

        return \is_string($idToken) ? $idToken : null;
    }
}
