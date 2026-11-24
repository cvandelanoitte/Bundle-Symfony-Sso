<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Security;

use Issl\SsoBundle\Oidc\AuthorizationRequest;
use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * Keeps the sign-ins in progress in the session, keyed by their "state".
 * Several at once (two tabs), a few at most, ten minutes each; a state can be
 * used only once.
 */
final readonly class PendingAuthorizationStore
{
    private const string SESSION_KEY = '_issl_sso.pending';
    private const int MAX_PENDING = 5;
    private const int LIFETIME = 600;

    public function __construct(
        private ClockInterface $clock,
    ) {
    }

    public function save(SessionInterface $session, AuthorizationRequest $authorization): void
    {
        $pending = $this->load($session);
        $pending[$authorization->state] = $authorization->toArray();
        $session->set(self::SESSION_KEY, \array_slice($pending, -self::MAX_PENDING, null, true));
    }

    /**
     * Returns and forgets the sign-in started with this state, or null when it
     * is unknown or expired.
     */
    public function pull(SessionInterface $session, string $state): ?AuthorizationRequest
    {
        $pending = $this->load($session);
        $authorization = AuthorizationRequest::fromArray($pending[$state] ?? null);
        unset($pending[$state]);
        $session->set(self::SESSION_KEY, $pending);

        return null !== $authorization && $authorization->state === $state ? $authorization : null;
    }

    /**
     * @return array<string, array<mixed>> the unexpired sign-ins
     */
    private function load(SessionInterface $session): array
    {
        $stored = $session->get(self::SESSION_KEY);
        if (!\is_array($stored)) {
            return [];
        }
        $oldest = $this->clock->now()->getTimestamp() - self::LIFETIME;
        $pending = [];
        foreach ($stored as $state => $data) {
            $authorization = AuthorizationRequest::fromArray($data);
            if (\is_string($state) && null !== $authorization && $authorization->createdAt >= $oldest) {
                $pending[$state] = $authorization->toArray();
            }
        }

        return $pending;
    }
}
